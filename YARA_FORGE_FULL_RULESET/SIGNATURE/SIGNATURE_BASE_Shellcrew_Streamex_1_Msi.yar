rule SIGNATURE_BASE_Shellcrew_Streamex_1_Msi : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "8cf5dad5-0737-56bf-8cef-7bcf7e7e5a78"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_shellcrew_streamex.yar#L61-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fa853dac58c067a88f1784ac4017fd558151e54ed10ceb32ab90c99e970460fe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"

	strings:
		$x1 = "msi.dll.eng" fullword wide
		$s2 = "ahinovx" fullword ascii
		$s3 = "jkpsxy47CDEMNSTYbhinqrwx56" fullword ascii
		$s4 = "PVYdejmrsy12" fullword ascii
		$s6 = "FLMTUZaijkpsxy45CD" fullword ascii
		$s7 = "afhopqvw34ABIJOPTYZehmo" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and 3 of them )
}
