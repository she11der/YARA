import "pe"

rule SIGNATURE_BASE_IMPLANT_5_V4
{
	meta:
		description = "XTunnel Implant by APT28"
		author = "US CERT"
		id = "db6df7ea-f119-5e9a-bcea-c65580418042"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L1209-L1225"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "98a08860453496d9629f62c64fed50a24b8378dcfa39b8b654610c2ac9084fa8"
		score = 85
		quality = 85
		tags = ""

	strings:
		$FBKEY1 = { 987AB999FE0924A2DF0A412B14E26093746FCDF9BA31DC05536892C33B116AD3 }
		$FBKEY2 = { 8B236C892D902B0C9A6D37AE4F9842C3070FBDC14099C6930158563C6AC00FF5 }
		$FBKEY3 = { E47B7F110CAA1DA617545567EC972AF3A6E7B4E6807B7981D3CFBD3D8FCC3373 }
		$FBKEY4 = { 48B284545CA1FA74F64FDBE2E605D68CED8A726D05EBEFD9BAAC164A7949BDC1 }
		$FBKEY5 = { FB421558E30FCCD95FA7BC45AC92D2991C44072230F6FBEAA211341B5BF2DC56 }

	condition:
		all of them
}
