rule SIGNATURE_BASE_FIN7_Dropper_Aug17 : FILE
{
	meta:
		description = "Detects Word Dropper from Proofpoint FIN7 Report"
		author = "Florian Roth (Nextron Systems)"
		id = "4929dff6-9f33-5d22-b560-c2195440a1cc"
		date = "2017-08-04"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fin7_backdoor.yar#L12-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "610b7288e08d36858de88abac3a86dcb6ebba1c019e17fb716f5c26aa964903b"
		score = 75
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c91642c0a5a8781fff9fd400bff85b6715c96d8e17e2d2390c1771c683c7ead9"
		hash2 = "cf86c7a92451dca1ebb76ebd3e469f3fa0d9b376487ee6d07ae57ab1b65a86f8"

	strings:
		$x1 = "tpircsj:e/ b// exe.tpircsw\" rt/" fullword ascii
		$s1 = "Scripting.FileSystemObject$" fullword ascii
		$s2 = "PROJECT.THISDOCUMENT.AUTOOPEN" fullword wide
		$s3 = "Project.ThisDocument.AutoOpen" fullword wide
		$s4 = "\\system3" ascii
		$s5 = "ShellV" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <700KB and 1 of ($x*) or all of ($s*))
}
