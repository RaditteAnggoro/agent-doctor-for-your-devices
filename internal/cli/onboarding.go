package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/discovery"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/session"
)

func cancelledAnswer(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cancel", "stop", "stop everything", "later", "postpone", "batal", "batalkan", "berhenti", "stop dulu", "cukup", "nanti", "tunda", "selesai":
		return true
	}
	return false
}
func skippedAnswer(s string) bool {
	if negative(s) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "skip", "lewati", "lanjut", "tidak usah", "-":
		return true
	}
	return false
}
func affirmative(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ya", "iya", "y", "yes", "lanjut", "mulai":
		return true
	}
	return false
}
func negative(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tidak", "nggak", "ngga", "gak", "ga", "no", "n", "jangan":
		return true
	}
	return false
}

// onboard keeps optional personal context local. Only explicit device/feature/
// scope answers leave this function; names and symptoms are never report fields.
func onboard(ctx context.Context, in io.Reader, out io.Writer, feature *string, all *bool, roots *listFlag, confirmed *bool) error {
	if _, ok := in.(*bufio.Reader); !ok {
		in = bufio.NewReaderSize(in, 8193)
	}
	ask := func(question string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		fmt.Fprintln(out, question)
		value, err := readAnswer(ctx, in)
		if err != nil {
			return "", err
		}
		if cancelledAnswer(value) {
			return "", context.Canceled
		}
		return value, nil
	}
	fmt.Fprintln(out, "Hai, selamat datang di Agent Doctor!")
	fmt.Fprintln(out, "Aku bantu kamu cek kondisi perangkat, dari storage sampai performa, lalu pilih langkah yang cocok. Kita mulai pelan-pelan, ya.")
	fmt.Fprintln(out, "Cek awal cuma baca data perangkat. Kalau nanti mau hapus atau uninstall, kamu tetap pilih target dan setujui rencananya dulu.")
	for {
		name, err := ask("Biar ngobrolnya enak, aku panggil kamu siapa? (Opsional; Enter atau ketik lewati kalau mau skip.)")
		if err != nil {
			return err
		}
		if skippedAnswer(name) {
			fmt.Fprintln(out, "Boleh, kita langsung lanjut aja.")
			break
		}
		if utf8.RuneCountInString(name) > 40 {
			fmt.Fprintln(out, "Nama panggilan cukup sampai 40 karakter, ya. Kamu juga boleh lewati.")
			continue
		}
		fmt.Fprintf(out, "Senang kenal kamu, %s! Nama panggilan ini cuma dipakai buat menyapa di sesi ini.\n", terminal(name))
		break
	}
	issue, err := ask("Lagi pengin dibantu soal apa? Misalnya perangkat terasa lemot, storage penuh, atau cek rutin. (Opsional; Enter atau lewati buat langsung pilih pemeriksaan.)")
	if err != nil {
		return err
	}
	if !skippedAnswer(issue) {
		fmt.Fprintln(out, "Oke, nanti kita cocokkan keluhan itu dengan hasil cek. Sekarang pilih dulu apa yang mau diperiksa.")
	}
	var target string
	for {
		choice, err := ask("Perangkat yang mau kita cek pakai OS apa?\n1. macOS\n2. Windows\n3. Linux\n4. ChromeOS\n5. Bantu deteksi (default)\nPilih nomor atau nama OS; Enter buat deteksi otomatis.")
		if err != nil {
			return err
		}
		var ok bool
		target, ok = operatingSystemChoice(choice)
		if ok {
			break
		}
		fmt.Fprintln(out, "Aku belum nangkap pilihan OS-nya. Belum ada pemeriksaan yang dimulai; pilih salah satu opsi tadi, ya.")
	}
	env := discovery.Detect()
	for {
		answer, err := ask(fmt.Sprintf("Aku mendeteksi host %s; CLI ini jalan di %s (%s), sesi remote: %s. Ini perangkat yang mau kamu cek? (ya/tidak)", osLabel(env.HostOS), osLabel(env.OS), terminal(env.Type), yesNo(env.Remote)))
		if err != nil {
			return err
		}
		if affirmative(answer) {
			break
		}
		if negative(answer) {
			return context.Canceled
		}
		fmt.Fprintln(out, "Belum aku lanjutkan. Ketik ya kalau perangkatnya benar, atau tidak buat berhenti.")
	}
	if target != "" && target != env.HostOS && target != env.OS {
		return errors.New("OS pilihanmu berbeda dari lingkungan yang terdeteksi. Jalankan Agent Doctor di perangkat yang ingin kamu cek; belum ada scan dimulai")
	}
	*confirmed = true
	for {
		choice, err := ask("Mau kita cek yang mana?\n1. File sisa (junk) — cache, file sementara, atau installer lama\n2. Performa — CPU, RAM, storage, dan info startup yang tersedia\n3. Aplikasi — ukuran, bukti terakhir dibuka, dan info buat review\n4. Duplikat — file dengan isi sama; isinya dibaca untuk verifikasi\n5. Semua\nPilih nomor atau nama fitur. Boleh beberapa, pisahkan dengan koma; contoh 1,3.")
		if err != nil {
			return err
		}
		selected, everything, ok := featureChoices(choice)
		if !ok {
			fmt.Fprintln(out, "Pilih dulu salah satu fitur tadi, ya. Pilihanmu belum aku ubah.")
			continue
		}
		*all = everything
		*feature = strings.Join(selected, ",")
		break
	}
	for {
		choice, err := ask("Enaknya hasilnya mau dibahas gimana?\n1. Cek + panduan review (default)\n2. Cek + laporan saja\nEnter buat pilihan 1.")
		if err != nil {
			return err
		}
		switch strings.ToLower(choice) {
		case "", "1", "review", "panduan", "lewati", "skip":
		case "2", "report", "laporan":
		default:
			fmt.Fprintln(out, "Pilih 1 buat panduan review atau 2 buat laporan saja, ya.")
			continue
		}
		break
	}
	if *all || strings.Contains(*feature, "junk") || strings.Contains(*feature, "duplicates") {
		for {
			path, err := ask("Folder mana yang boleh aku periksa? Tulis lokasinya, misalnya ~/Downloads. Folder terlindungi/cloud, symlink, dan volume lain tetap dilewati.")
			if err != nil {
				return err
			}
			if path == "" {
				fmt.Fprintln(out, "Aku perlu pilihan folder yang jelas dulu. Boleh tulis lokasinya atau ketik batal.")
				continue
			}
			parentTraversal := false
			for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
				if part == ".." {
					parentTraversal = true
					break
				}
			}
			if parentTraversal {
				fmt.Fprintln(out, "Tulis lokasi folder lengkap tanpa .., ya, supaya cakupannya jelas.")
				continue
			}
			if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				path = filepath.Join(home, strings.TrimLeft(path[1:], `/\`))
			}
			approved, err := safety.Root(path)
			if err != nil {
				fmt.Fprintf(out, "Folder itu belum bisa dipakai: %s\nCoba lokasi lain, atau ketik batal.\n", terminal(err.Error()))
				continue
			}
			*roots = listFlag{approved}
			break
		}
	}
	return nil
}
func operatingSystemChoice(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "macos", "mac os", "mac", "darwin", "os x", "osx":
		return "darwin", true
	case "2", "windows", "win":
		return "windows", true
	case "3", "linux":
		return "linux", true
	case "4", "chromeos", "chrome os", "chromebook":
		return "chromeos", true
	case "", "5", "detect", "detect for me", "bantu deteksi", "deteksi", "otomatis", "deteksi otomatis", "skip", "lewati":
		return "", true
	}
	return "", false
}
func featureChoices(s string) ([]string, bool, bool) {
	aliases := map[string]string{"1": "junk", "junk": "junk", "file sisa": "junk", "file sampah": "junk", "cache": "junk", "2": "performance", "performance": "performance", "performa": "performance", "3": "applications", "applications": "applications", "aplikasi": "applications", "apps": "applications", "4": "duplicates", "duplicates": "duplicates", "duplikat": "duplicates", "5": "all", "all": "all", "semua": "all"}
	selected := []string{}
	seen := map[string]bool{}
	all := false
	for _, part := range strings.Split(strings.ToLower(strings.TrimSpace(s)), ",") {
		f, ok := aliases[strings.TrimSpace(part)]
		if !ok {
			return nil, false, false
		}
		if f == "all" {
			all = true
		} else if !seen[f] {
			selected = append(selected, f)
			seen[f] = true
		}
	}
	if all {
		return []string{}, true, true
	}
	return selected, false, len(selected) > 0
}
func osLabel(s string) string {
	switch s {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "chromeos":
		return "ChromeOS"
	case "unknown", "":
		return "belum diketahui"
	}
	return terminal(s)
}
func yesNo(b bool) string {
	if b {
		return "ya"
	}
	return "tidak"
}
func featureLabel(s string) string {
	switch s {
	case "junk":
		return "file sisa"
	case "performance":
		return "performa"
	case "applications":
		return "aplikasi"
	case "duplicates":
		return "duplikat"
	}
	return terminal(s)
}

func interactiveSummary(out io.Writer, env findings.Environment, features []string, scope findings.Scope, timeout, sample time.Duration, store bool, dataDir string) error {
	names := []string{}
	for _, f := range features {
		names = append(names, featureLabel(f))
	}
	fmt.Fprintln(out, "Oke, sebelum mulai, kita pastikan pilihannya dulu:")
	fmt.Fprintf(out, "- Host: %s; CLI: %s; lingkungan: %s; remote: %s\n", osLabel(env.HostOS), osLabel(env.OS), terminal(env.Type), yesNo(env.Remote))
	fmt.Fprintln(out, "- Yang dicek:", strings.Join(names, ", "))
	if len(scope.Roots) == 0 {
		fmt.Fprintln(out, "- Cakupan: metadata fitur yang kamu pilih; tidak ada penelusuran folder umum.")
	} else {
		for _, root := range scope.Roots {
			fmt.Fprintln(out, "- Folder:", terminal(root))
		}
	}
	fmt.Fprintln(out, "- Folder terlindungi, cloud yang dikenali, symlink, dan perpindahan volume tetap dilewati.")
	for _, path := range scope.Exclusions {
		fmt.Fprintln(out, "- Pengecualian tambahan:", terminal(path))
	}
	fmt.Fprintf(out, "- Batas: %d entri, kedalaman %d, pembacaan isi maksimal %d byte, waktu %s; sampel CPU %s.\n", scope.MaxFiles, scope.MaxDepth, scope.MaxBytes, timeout, sample)
	if store {
		if dataDir == "" {
			var err error
			dataDir, err = session.DefaultDir()
			if err != nil {
				return fmt.Errorf("lokasi laporan belum bisa ditentukan: %w", err)
			}
		}
		fmt.Fprintln(out, "- Laporan disimpan lokal di:", terminal(dataDir))
	} else {
		fmt.Fprintln(out, "- Hasil tampil di terminal; laporan tidak disimpan ke file.")
	}
	fmt.Fprintln(out, "Pemeriksaan ini cuma baca data perangkat. Lanjut cek sekarang? (ya/tidak)")
	return nil
}
