import "pe"

rule SIGNATURE_BASE_Agent_BTZ_Proxy_DLL_1 : FILE
{
	meta:
		description = "Detects Agent-BTZ Proxy DLL - activeds.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "f8032616-2a54-5107-b330-65fcc84b866e"
		date = "2017-08-07"
		modified = "2023-12-05"
		reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_agent_btz.yar#L13-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ea430b2888b487a5c7a91b73e8a7893b53d67e8ac95ae85fe9d15c633b2ee660"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9c163c3f2bd5c5181147c6f4cf2571160197de98f496d16b38c7dc46b5dc1426"
		hash2 = "628d316a983383ed716e3f827720915683a8876b54677878a7d2db376d117a24"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Modules" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them and pe.exports("Entry"))
}
