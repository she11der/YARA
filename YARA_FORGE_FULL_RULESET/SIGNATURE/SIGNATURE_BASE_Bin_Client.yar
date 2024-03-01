rule SIGNATURE_BASE_BIN_Client
{
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "515ab1b3-7923-55de-8c19-71ef5d9b4366"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7561-L7577"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9f0a74ec81bc2f26f16c5c172b80eca7"
		logic_hash = "e1277f6b7adc2e832a3aad96c7e44796596d2e61eb9247977da3c3569777e0b2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "=====Remote Shell Closed====="
		$s2 = "All Files(*.*)|*.*||"
		$s6 = "WSAStartup Error!"
		$s7 = "SHGetFileInfoA"
		$s8 = "CreateThread False!"
		$s9 = "Port Number Error"

	condition:
		4 of them
}
