rule SIGNATURE_BASE_COZY_FANCY_BEAR_Pagemgr_Hunt : FILE
{
	meta:
		description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
		author = "Florian Roth (Nextron Systems)"
		id = "3c5c8843-81ba-510c-82ed-4b6e2286bdb2"
		date = "2016-06-14"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fancybear_dnc.yar#L30-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c6055b7cd04b994c80395276e83bec664b7dd32f8093411bfde0850cca39e9f7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "pagemgr.exe" wide fullword

	condition:
		uint16(0)==0x5a4d and 1 of them
}
