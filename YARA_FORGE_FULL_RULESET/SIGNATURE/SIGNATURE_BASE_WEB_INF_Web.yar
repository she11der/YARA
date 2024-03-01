rule SIGNATURE_BASE_WEB_INF_Web : FILE
{
	meta:
		description = "Laudanum Injector Tools - file web.xml"
		author = "Florian Roth (Nextron Systems)"
		id = "8d0a008c-56d1-59ef-8521-0697add21ba9"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_laudanum_webshells.yar#L193-L207"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
		logic_hash = "b58bb63a5268812ed6a5d18c8da96b0fdae33e4802a2fba4964ab69e92517a16"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<servlet-name>Command</servlet-name>" fullword ascii
		$s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii

	condition:
		filesize <1KB and all of them
}
