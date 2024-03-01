rule SIGNATURE_BASE_Soaksoak_Infected_Wordpress
{
	meta:
		description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
		author = "Florian Roth (Nextron Systems)"
		id = "d147af65-72de-50be-9435-bef47eb4842a"
		date = "2014-12-15"
		modified = "2023-12-05"
		reference = "http://goo.gl/1GzWUX"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9132-L9147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4cba18a0d14be2795d71a1973265a1742beda57636f64c1974001ecf70e3e91d"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
		$s1 = "function FuncQueueObject()" ascii fullword
		$s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword

	condition:
		all of ($s*)
}
