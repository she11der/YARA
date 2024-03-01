rule SIGNATURE_BASE_CN_Honker_Webshell_Test3693 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file test3693.war"
		author = "Florian Roth (Nextron Systems)"
		id = "58fe4445-b2e1-5d5f-8c46-39c6ae78f845"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L25-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "246d629ae3ad980b5bfe7e941fe90b855155dbfc"
		logic_hash = "a10618d54fb7adbbd89a10f2e1ac067ccd1832140bcaf3b92394ebe7323f2d1e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii
		$s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii

	condition:
		uint16(0)==0x4b50 and filesize <50KB and all of them
}
