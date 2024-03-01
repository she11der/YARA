import "pe"

rule SIGNATURE_BASE_Sig_238_Findoor
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file findoor.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "61215a76-8c29-505d-bfef-a5f13fec476c"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2590-L2607"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
		logic_hash = "223f324ab6b61775d500dc248b9db8363ce915ec279a893a6f0ec92b273a27c0"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "(non-Win32 .EXE or error in .EXE image)." fullword ascii
		$s8 = "PASS hacker@hacker.com" fullword ascii
		$s9 = "/scripts/..%c1%1c../winnt/system32/cmd.exe" fullword ascii
		$s10 = "MAIL FROM:hacker@hacker.com" fullword ascii
		$s11 = "http://isno.yeah.net" fullword ascii

	condition:
		4 of them
}
