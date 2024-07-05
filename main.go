package main

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/chromedp/chromedp"
	"github.com/lucasb-eyer/go-colorful"
	"golang.org/x/image/bmp"
)

const distance = 0.1

//go:embed index.htm
var tpl string

func randomText() (template.HTML, error) {
	res, err := http.Get("https://api.ganjoor.net/api/ganjoor/poem/random?poetId=2")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var m map[string]any
	if err = json.Unmarshal(data, &m); err != nil {
		return "", err
	}

	str, ok := m["plainText"].(string)

	if !ok {
		return "", errors.New("invalid response")
	}

	return template.HTML(str), nil
}

func main() {
	tplExec := template.Must(template.New("daily").Parse(tpl))
	txt, err := randomText()
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {

		tplExec.Execute(w, map[string]any{
			"Now":  time.Now().Format(time.RFC3339),
			"Poet": txt,
		})
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	addr := listener.Addr().(*net.TCPAddr).Port
	go func() {
		http.Serve(listener, nil)
	}()
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	var buf []byte
	err = chromedp.Run(ctx,
		chromedp.EmulateViewport(800, 480),
		chromedp.Navigate(fmt.Sprintf("http://127.0.0.1:%d", addr)),
		chromedp.CaptureScreenshot(&buf),
	)

	if err != nil {
		panic(err)
	}
	reader := bytes.NewBuffer(buf)

	pngImage, err := png.Decode(reader)
	if err != nil {
		panic(err)
	}

	r := image.Rectangle{
		Min: image.Point{
			X: 0, Y: 0,
		},
		Max: image.Point{
			X: 800, Y: 480,
		},
	}

	black := image.NewGray(r)
	red := image.NewGray(r)

	rC, _ := colorful.Hex("#FF0000")
	bC, _ := colorful.Hex("#000000")
	bW, _ := colorful.Hex("#FFFFFF")

	for y := pngImage.Bounds().Min.Y; y < pngImage.Bounds().Max.Y; y++ {
		for x := pngImage.Bounds().Min.X; x < pngImage.Bounds().Max.X; x++ {
			clr, _ := colorful.MakeColor(pngImage.At(x, y))
			if clr.DistanceLab(rC) < distance {
				red.Set(x, y, bC)
				black.Set(x, y, bW)
			} else if clr.DistanceLab(bC) < distance {
				black.Set(x, y, bC)
				red.Set(x, y, bW)
			} else {
				red.Set(x, y, bW)
				black.Set(x, y, bW)
			}
		}
	}
	pub := os.Getenv("PUBLIC_KEY")

	recipient, err := readGPGPublic(pub)
	if err != nil {
		panic(err)
	}

	bF := &bytes.Buffer{}
	rF := &bytes.Buffer{}
	if err = encrypt([]*openpgp.Entity{recipient}, nil, black, bF); err != nil {
		panic(err)
	}
	if err = encrypt([]*openpgp.Entity{recipient}, nil, red, rF); err != nil {
		panic(err)
	}

	zW, err := os.Create("public/bundle.zip")
	if err != nil {
		panic(err)
	}

	defer zW.Close()

	if err = zipFiles(bF, rF, zW); err != nil {
		panic(err)
	}

}

func readGPGPublic(data string) (*openpgp.Entity, error) {
	buf := bytes.NewBufferString(data)
	block, err := armor.Decode(buf)
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

func encrypt(recip []*openpgp.Entity, signer *openpgp.Entity, img image.Image, w io.Writer) error {
	buf := bytes.NewBuffer(nil)
	if err := bmp.Encode(buf, img); err != nil {
		return err
	}

	wc, err := openpgp.Encrypt(w, recip, signer, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return err
	}

	if _, err := io.Copy(wc, buf); err != nil {
		return err
	}
	return wc.Close()
}

func zipFiles(black, red *bytes.Buffer, w io.Writer) error {
	zW := zip.NewWriter(w)
	b, err := zW.Create("black.bmp.enc")
	if err != nil {
		return err
	}
	if _, err = io.Copy(b, black); err != nil {
		return err
	}

	r, err := zW.Create("red.bmp.enc")
	if err != nil {
		return err
	}
	if _, err = io.Copy(r, red); err != nil {
		return err
	}

	return zW.Close()
}
