rule SIGNATURE_BASE_SUSP_Just_EICAR : FILE
{
	meta:
		description = "Just an EICAR test file - this is boring but users asked for it"
		author = "Florian Roth (Nextron Systems)"
		id = "e5eedd77-36e2-56a0-be0c-2553043c225a"
		date = "2019-03-24"
		modified = "2023-12-05"
		reference = "http://2016.eicar.org/85-0-Download.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L344-L357"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a48fc3542fb07131fe0a2e25277009d21b9ca7c9e112873249e5b9c31511af79"
		score = 40
		quality = 85
		tags = "FILE"
		hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

	strings:
		$s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii

	condition:
		uint16(0)==0x3558 and filesize <70 and $s1 at 0
}
