rule SIGNATURE_BASE_CN_Honker_ASP_Wshell : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wshell.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "028136cd-129b-5d58-a4c2-ba730a798c06"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L83-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3ae33c835e7ea6d9df74fe99fcf1e2fb9490c978"
		logic_hash = "f6f83acb76248a1b00f1acac621e68888c93b34d4813d8f8613d5d9095c53a8a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
		$s1 = "UserPass="
		$s2 = "VerName="
		$s3 = "StateName="

	condition:
		uint16(0)==0x253c and filesize <200KB and all of them
}
