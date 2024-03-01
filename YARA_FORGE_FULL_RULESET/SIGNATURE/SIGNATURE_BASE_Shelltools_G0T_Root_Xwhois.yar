rule SIGNATURE_BASE_Shelltools_G0T_Root_Xwhois
{
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8f3b3bb2-5884-584a-8220-b6edbfebc8a3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8851-L8865"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0bc98bd576c80d921a3460f8be8816b4"
		logic_hash = "75ee56dae5fde75ae4dc4bba835a96016781b747f3cff0dc6d52e665463a6070"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "rting! "
		$s2 = "aTypCog("
		$s5 = "Diamond"
		$s6 = "r)r=rQreryr"

	condition:
		all of them
}
