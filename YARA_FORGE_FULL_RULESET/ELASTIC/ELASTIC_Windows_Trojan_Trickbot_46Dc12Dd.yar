rule ELASTIC_Windows_Trojan_Trickbot_46Dc12Dd : FILE MEMORY
{
	meta:
		description = "Targets newBCtestDll64 module containing reverse shell functionality"
		author = "Elastic Security"
		id = "46dc12dd-d81a-43a6-b7c3-f59afa1c863e"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Trickbot.yar#L504-L528"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "bf38a787aee5afdcab00b95ccdf036bc7f91f07151b4444b54165bb70d649ce5"
		logic_hash = "e01209a83f4743cbad7dda01595c053277868bd47208e48214b557ae339b5b3c"
		score = 50
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "997fe1c5a06bfffb754051436c48a0538ff2dcbfddf0d865c3a3797252247946"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "setconf" ascii fullword
		$a2 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
		$a3 = "nf\" file = \"bcconfig\" period = \"90\"/></autoconf></moduleconfig>" ascii fullword
		$a4 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
		$a5 = "<addr>" ascii fullword
		$a6 = "</addr>" ascii fullword

	condition:
		4 of ($a*)
}
