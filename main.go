package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/png"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cshum/vipsgen/vips"
	"golang.org/x/image/bmp"
)

const (
	DefaultMaxUploadBytes           = 10 << 20
	DefaultTimeoutSec               = 30
	DefaultConcurrencyImgProcessing = 10
	DefaultMaxHeaderBytes           = 1 << 20
	DefaultMaxCacheFiles            = 200
	DefaultMaxCacheMem              = 50 * 1024 * 1024
	DefaultMaxCacheSize             = 200
)

type TargetConversion string

const (
	KeepOriginal TargetConversion = "KEEP_ORIGINAL"
	Jpeg         TargetConversion = "JPEG"
	Png          TargetConversion = "PNG"
	WebP         TargetConversion = "WEBP"
	Bmp          TargetConversion = "BMP"
)

var (
	addr                     string
	maxUploadFlag            int
	maxHeaderBytes           int
	readTimeout              int
	writeTimeout             int
	idleTimeout              int
	maxWorkers               int
	imgProcessingConcurrency int
	maxCacheFiles            int
	maxCacheMem              int
	maxCacheSize             int
	vectorEnabled            bool
)

var sem chan struct{}

type ResizeOptions struct {
	KeepAspectRatio bool `json:"keepAspectRatio"`
	Width           int  `json:"width"`
	Height          int  `json:"height"`
}

type Options struct {
	QualityPercent   int               `json:"qualityPercent"`
	TargetConversion *TargetConversion `json:"targetConversion"`
	ResizeOptions    *ResizeOptions    `json:"resizeOptions"`
}

func main() {
	parseEnvVariables()
	conf := vips.Config{
		MaxCacheFiles:    maxCacheFiles,
		MaxCacheMem:      maxCacheMem,
		MaxCacheSize:     maxCacheSize,
		ConcurrencyLevel: imgProcessingConcurrency,
		VectorEnabled:    vectorEnabled,
	}

	vips.Startup(&conf)
	defer vips.Shutdown()

	if maxWorkers <= 0 {
		maxWorkers = runtime.GOMAXPROCS(0) * 2
	}

	sem = make(chan struct{}, maxWorkers)

	mux := &http.ServeMux{}
	mux.HandleFunc("/convert", withPanicLogic(convertHandler))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(readTimeout) * time.Second,
		WriteTimeout:      time.Duration(writeTimeout) * time.Second,
		IdleTimeout:       time.Duration(idleTimeout) * time.Second,
		MaxHeaderBytes:    maxUploadFlag,
	}

	// graceful shutdown
	idleConnections := make(chan struct{})
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("shutdown signal received, shutting down http server...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		close(idleConnections)
	}()

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	log.Printf("listening on %s, maxWorkers=%d", srv.Addr, maxWorkers)

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
	<-idleConnections
	log.Println("http server stopped")
}

func withPanicLogic(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic: %v", p)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		h(w, r)
	}
}

func convertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	maxUpload := maxUploadFlag
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxUpload))

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid request form: "+err.Error(), http.StatusBadRequest)
		return
	}

	optsStr := r.FormValue("options")
	if strings.TrimSpace(optsStr) == "" {
		http.Error(w, "invalid request form: options is empty", http.StatusBadRequest)
		return
	}

	var opts Options

	if err := json.Unmarshal([]byte(optsStr), &opts); err != nil {
		http.Error(w, "invalid options JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")

	if err != nil {
		http.Error(w, "missing file part 'file' for conversion: "+err.Error(), http.StatusBadRequest)
		return
	}

	defer func(file multipart.File) {
		err := file.Close()
		if err != nil {
			log.Printf("Could not close file: %v", err)
		}
	}(file)

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, file); err != nil {
		http.Error(w, "failed reading uploaded file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	input := buf.Bytes()

	if len(input) == 0 {
		http.Error(w, "empty file", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(readTimeout)*time.Second)
	defer cancel()

	select {
	case sem <- struct{}{}:
	// acquired
	case <-ctx.Done():
		http.Error(w, "request timed out waiting for worker! Increase workers or timeout or throttle requests", http.StatusServiceUnavailable)
		return
	}
	defer func() {
		<-sem
	}()

	outBytes, outMime, err := processWithVips(ctx, input, opts)

	if err != nil {
		log.Printf("processing error: %v", err)
		http.Error(w, "processing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ext := guessExtensionFromMime(outMime)
	if ext == "" {
		ext = filepath.Ext(header.Filename)
	}
	if ext == "" {
		ext = ".img"
	}

	outFilename := strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename)) + ext

	w.Header().Set("Content-Type", outMime)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", outFilename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outBytes)))
	_, _ = w.Write(outBytes)
}

func processWithVips(ctx context.Context, input []byte, opts Options) ([]byte, string, error) {
	if opts.QualityPercent < 0 {
		opts.QualityPercent = 0
	}
	if opts.QualityPercent > 100 {
		opts.QualityPercent = 100
	}

	if opts.ResizeOptions != nil {
		if opts.ResizeOptions.KeepAspectRatio && opts.ResizeOptions.Width <= 0 {
			return nil, "", errors.New("width must be greater than 0 when using keepAspectRatio=true")
		}
		if !opts.ResizeOptions.KeepAspectRatio && opts.ResizeOptions.Height <= 0 && opts.ResizeOptions.Width <= 0 {
			return nil, "", errors.New("width or height must be greater than 0 when using keepAspectRatio=false")
		}
	}

	img, err := vips.NewImageFromBuffer(input, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create image from buffer: %w", err)
	}
	defer img.Close()

	if opts.ResizeOptions == nil && opts.TargetConversion != nil && *opts.TargetConversion == KeepOriginal {
		mimeType := mime.TypeByExtension(guessExtensionFromVipsType(img.Format()))
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
		return input, mimeType, nil
	}

	origW := img.Width()
	origH := img.Height()

	if opts.ResizeOptions != nil {
		if opts.ResizeOptions.KeepAspectRatio {
			scale := float64(opts.ResizeOptions.Width) / float64(origW)
			if scale <= 0 {
				return nil, "", errors.New("invalid calculation for scale")
			}
			if err := img.Resize(scale, nil); err != nil {
				return nil, "", fmt.Errorf("failed to resize image: %w", err)
			}
		} else {
			hScale := float64(opts.ResizeOptions.Height) / float64(origH)
			wScale := float64(opts.ResizeOptions.Width) / float64(origW)
			if err := img.Resize(wScale, &vips.ResizeOptions{
				Vscale: hScale,
				Kernel: vips.KernelNearest,
			}); err != nil {
				return nil, "", fmt.Errorf("failed to resize image: %w", err)
			}
		}
	}

	if opts.TargetConversion != nil {
		alphaCheck := *opts.TargetConversion == Jpeg || *opts.TargetConversion == Bmp
		if alphaCheck || (*opts.TargetConversion == KeepOriginal && (img.Format() == vips.ImageTypeJpeg || img.Format() == vips.ImageTypeBmp)) {
			hasAlpha := img.HasAlpha()
			if hasAlpha {
				_ = img.Flatten(&vips.FlattenOptions{
					Background: []float64{255, 255, 255},
					MaxAlpha:   255,
				})
			}
		}
	} else {
		*opts.TargetConversion = KeepOriginal
	}

	var out []byte
	var exportError error
	var outMime string

	done := make(chan struct{})
	go func() {
		defer close(done)
		switch *opts.TargetConversion {
		case KeepOriginal:
			switch img.Format() {
			case vips.ImageTypeJpeg:
				out, exportError = img.JpegsaveBuffer((*vips.JpegsaveBufferOptions)(&vips.JpegsaveOptions{Q: opts.QualityPercent}))
				outMime = "image/jpeg"
				break
			case vips.ImageTypePng:
				out, exportError = savePng(img, &opts)
				outMime = "image/png"
				break
			case vips.ImageTypeWebp:
				out, exportError = img.WebpsaveBuffer((*vips.WebpsaveBufferOptions)(&vips.WebpsaveOptions{Q: opts.QualityPercent}))
				outMime = "image/webp"
				break
			case vips.ImageTypeBmp:
				out, exportError = convertToBMP(img, &opts)
				outMime = "image/bmp"
				break
			default:
				outMime = "image/jpeg"
			}
		case Jpeg:
			out, exportError = img.JpegsaveBuffer((*vips.JpegsaveBufferOptions)(&vips.JpegsaveOptions{Q: opts.QualityPercent}))
			outMime = "image/jpeg"
			break
		case Png:
			out, exportError = savePng(img, &opts)
			outMime = "image/png"
			break
		case WebP:
			out, exportError = img.WebpsaveBuffer((*vips.WebpsaveBufferOptions)(&vips.WebpsaveOptions{Q: opts.QualityPercent}))
			outMime = "image/webp"
			break
		case Bmp:
			out, exportError = convertToBMP(img, &opts)
			outMime = "image/bmp"
			break
		default:
			exportError = errors.New("unknown target conversion")
		}
	}()

	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-done:
		if exportError != nil {
			return nil, "", fmt.Errorf("conversion of image failed: %w", exportError)
		}
	}

	return out, outMime, nil
}

func savePng(img *vips.Image, opts *Options) ([]byte, error) {
	compression := 9 * (100 - opts.QualityPercent) / 100
	if compression < 0 {
		compression = 0
	} else if compression > 9 {
		compression = 9
	}
	png, err := img.PngsaveBuffer((*vips.PngsaveBufferOptions)(&vips.PngsaveOptions{Q: compression}))
	return png, err
}

func convertToBMP(img *vips.Image, opts *Options) ([]byte, error) {
	raw, err := savePng(img, opts)
	if err != nil {
		return nil, fmt.Errorf("png intermediate export failed for bmp fallback: %w", err)
	}
	im, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode itermediate png failed: %w", err)
	}
	var outBuf bytes.Buffer
	if err := bmp.Encode(&outBuf, im); err != nil {
		return nil, fmt.Errorf("bmp encode failed: %w", err)
	}
	return outBuf.Bytes(), nil
}

func guessExtensionFromVipsType(t vips.ImageType) string {
	switch t {
	case vips.ImageTypeJpeg:
		return ".jpg"
	case vips.ImageTypePng:
		return ".png"
	case vips.ImageTypeWebp:
		return ".webp"
	default:
		return ""
	}
}

func guessExtensionFromMime(m string) string {
	extensions, _ := mime.ExtensionsByType(m)
	if len(extensions) > 0 {
		return extensions[0]
	}
	switch m {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	default:
		return ""
	}
}

func parseEnvVariables() {
	serverListeningPort := os.Getenv("ListeningPort")
	if serverListeningPort != "" {
		addr = ":" + serverListeningPort
	} else {
		addr = ":8080"
	}
	maxUpFlag := os.Getenv("MaxUploadBytes")
	if maxUpFlag != "" {
		maxUploadFlag, _ = strconv.Atoi(maxUpFlag)
	} else {
		maxUploadFlag = DefaultMaxUploadBytes
	}
	timeout := os.Getenv("ReadTimeoutSec")
	if timeout != "" {
		readTimeout, _ = strconv.Atoi(timeout)
	} else {
		readTimeout = DefaultTimeoutSec
	}
	wTimeout := os.Getenv("WriteTimeoutSec")
	if wTimeout != "" {
		writeTimeout, _ = strconv.Atoi(wTimeout)
	} else {
		writeTimeout = readTimeout * 2
	}
	iTimeout := os.Getenv("IdleTimeoutSec")
	if iTimeout != "" {
		idleTimeout, _ = strconv.Atoi(iTimeout)
	} else {
		idleTimeout = readTimeout * 2
	}
	serWorkers := os.Getenv("MaxWorkers")
	if serWorkers != "" {
		maxWorkers, _ = strconv.Atoi(serWorkers)
	} else {
		maxWorkers = 0
	}
	hBytes := os.Getenv("MaxHeaderBytes")
	if hBytes != "" {
		maxHeaderBytes, _ = strconv.Atoi(hBytes)
	} else {
		maxHeaderBytes = DefaultMaxHeaderBytes
	}
	imgProcessingCon := os.Getenv("VipsImageProcessingConcurrency")
	if imgProcessingCon != "" {
		imgProcessingConcurrency, _ = strconv.Atoi(imgProcessingCon)
	} else {
		imgProcessingConcurrency = DefaultConcurrencyImgProcessing
	}
	mCacheFiles := os.Getenv("VipsMaxCacheFiles")
	if mCacheFiles != "" {
		maxCacheFiles, _ = strconv.Atoi(mCacheFiles)
	} else {
		maxCacheFiles = DefaultMaxCacheFiles
	}
	mCacheMem := os.Getenv("VipsMaxCacheMem")
	if mCacheMem != "" {
		maxCacheMem, _ = strconv.Atoi(mCacheMem)
	} else {
		maxCacheMem = DefaultMaxCacheMem
	}
	mCacheSize := os.Getenv("VipsMaxCacheSize")
	if mCacheSize != "" {
		maxCacheSize, _ = strconv.Atoi(mCacheSize)
	} else {
		maxCacheSize = DefaultMaxCacheSize
	}
	vectorEnabledStr := os.Getenv("VipsVectorEnabled")
	if vectorEnabledStr != "" {
		vectorEnabled, _ = strconv.ParseBool(vectorEnabledStr)
	} else {
		vectorEnabled = false
	}

	log.Printf("Configuration: listeningAddress: %s | maxUpload: %d | maxHeaderBytes: %d | readTimeout: %d | writeTimeout: %d | idleTimeout: %d | serverWorkers: %d | vipsImgProcessingConcurrency: %d | vipsMaxCacheFiles: %d | vipsMaxCacheMem: %d | vipsMaxCacheSize: %d | vipsVectorEnabled: %v",
		addr, maxUploadFlag, maxHeaderBytes, readTimeout, writeTimeout, idleTimeout, maxWorkers, imgProcessingConcurrency, maxCacheFiles, maxCacheMem, maxCacheSize, vectorEnabled)
}
