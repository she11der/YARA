rule ELASTIC_Windows_Trojan_Cobaltstrike_09B79Efa : FILE MEMORY
{
	meta:
		description = "Identifies Invoke Assembly module from Cobalt Strike"
		author = "Elastic Security"
		id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L203-L232"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "75fd003b9adf03aff8479b1b10da9c94955870b5fa4f1958f870e14acb2793c7"
		score = 75
		quality = 48
		tags = "FILE, MEMORY"
		fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "invokeassembly.x64.dll" ascii fullword
		$a2 = "invokeassembly.dll" ascii fullword
		$b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
		$b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
		$b3 = "[-] Failed to create the runtime host" ascii fullword
		$b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
		$b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
		$b6 = "ReflectiveLoader"
		$b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
		$b8 = "[-] No .NET runtime found. :(" ascii fullword
		$b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
		$c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }

	condition:
		1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}
