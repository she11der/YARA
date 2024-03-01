rule SIGNATURE_BASE_Wscriptshell_Case_Anomaly : FILE
{
	meta:
		description = "Detects obfuscated wscript.shell commands"
		author = "Florian Roth (Nextron Systems)"
		id = "d69d932d-1e39-5259-9200-f0227754f49c"
		date = "2017-09-11"
		modified = "2022-06-09"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_case_anomalies.yar#L62-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5c64e124186ae2eb974639627287fb27fe27eb2855342703e4a27a9c0fd62a91"
		score = 60
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "WScript.Shell\").Run" nocase ascii wide
		$sn1 = "WScript.Shell\").Run" ascii wide
		$sn2 = "wscript.shell\").run" ascii wide
		$sn3 = "WSCRIPT.SHELL\").RUN" ascii wide
		$sn4 = "Wscript.Shell\").Run" ascii wide
		$sn5 = "WScript.shell\").Run" ascii wide

	condition:
		filesize <3000KB and #s1>#sn1+#sn2+#sn3+#sn4+#sn5
}
