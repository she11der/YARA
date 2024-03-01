import "pe"

rule SIGNATURE_BASE_Psattack_ZIP : FILE
{
	meta:
		description = "PSAttack - Powershell attack tool - file PSAttack.zip"
		author = "Florian Roth (Nextron Systems)"
		id = "4e064eb4-0b87-590c-9ee4-6764b982c006"
		date = "2016-03-09"
		modified = "2023-12-05"
		reference = "https://github.com/gdssecurity/PSAttack/releases/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3174-L3188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2"
		logic_hash = "4c869e8663b8c87780d4be622f86b3887511e1ac3cfc67767f1c986af7d43767"
		score = 100
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PSAttack.exe" fullword ascii

	condition:
		uint16(0)==0x4b50 and all of them
}
