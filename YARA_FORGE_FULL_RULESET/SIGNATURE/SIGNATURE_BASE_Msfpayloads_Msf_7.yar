rule SIGNATURE_BASE_Msfpayloads_Msf_7
{
	meta:
		description = "Metasploit Payloads - file msf.vba"
		author = "Florian Roth (Nextron Systems)"
		id = "8d1b742e-510a-5807-ad3f-f10cc325d292"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L179-L194"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "167d295de5ffc9c88cf72f086fef4514f08cc3b9dd2d93b3ec36acffd6430370"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"

	strings:
		$s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
		$s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
		$s3 = "= RtlMoveMemory(" ascii

	condition:
		all of them
}
