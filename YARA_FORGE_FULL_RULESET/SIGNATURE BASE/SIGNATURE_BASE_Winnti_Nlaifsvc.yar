rule SIGNATURE_BASE_Winnti_Nlaifsvc : FILE
{
	meta:
		description = "Winnti sample - file NlaifSvc.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "d2bfcad4-9762-5f2a-88cc-e8cdc648e710"
		date = "2017-01-25"
		modified = "2023-12-05"
		reference = "https://goo.gl/VbvJtL"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_winnti_ms_report_201701.yar#L26-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7268c79baf37174e04b391ae42cdd6014f17478c5b89d0c7b8042eb839324f87"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "964f9bfd52b5a93179b90d21705cd0c31461f54d51c56d558806fe0efff264e5"

	strings:
		$x1 = "cracked by ximo" ascii
		$s1 = "Yqrfpk" fullword ascii
		$s2 = "IVVTOC" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 2 of them )) or (3 of them )
}
