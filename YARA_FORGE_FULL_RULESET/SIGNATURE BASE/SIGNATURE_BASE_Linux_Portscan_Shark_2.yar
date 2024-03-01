import "pe"

rule SIGNATURE_BASE_Linux_Portscan_Shark_2
{
	meta:
		description = "Detects Linux Port Scanner Shark"
		author = "Florian Roth (Nextron Systems)"
		id = "eea378d5-0399-5035-8573-139878fa1abc"
		date = "2016-04-01"
		modified = "2023-12-05"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3218-L3235"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "45efbbe01c45065efc07e9c75b6a7cdcae469861f84df4a1e1381fe864f7ddc0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "5f80bd2db608a47e26290f3385eeb5bfc939d63ba643f06c4156704614def986"
		hash2 = "90af44cbb1c8a637feda1889d301d82fff7a93b0c1a09534909458a64d8d8558"

	strings:
		$s1 = "usage: %s <fisier ipuri> <fisier useri:parole> <connect timeout> <fail2ban wait> <threads> <outfile> <port>" fullword ascii
		$s2 = "Difference between server modulus and host modulus is only %d. It's illegal and may not work" fullword ascii
		$s3 = "rm -rf scan.log" fullword ascii

	condition:
		all of them
}
