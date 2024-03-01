import "pe"

rule SIGNATURE_BASE_Psattack_EXE : FILE
{
	meta:
		description = "PSAttack - Powershell attack tool - file PSAttack.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "87f7956a-f607-5e14-a940-5080499cf682"
		date = "2016-03-09"
		modified = "2023-01-06"
		reference = "https://github.com/gdssecurity/PSAttack/releases/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3135-L3155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ad05d75640c850ee7eeee26422ba4f157be10a4e2d6dc6eaa19497d64cf23715"
		logic_hash = "b73566eb6370fbe68f0477d1179e5d6c19fb9be2c29f63d560c42adcdf19fe58"
		score = 100
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "\\Release\\PSAttack.pdb"
		$s1 = "set-executionpolicy bypass -Scope process -Force" fullword wide
		$s2 = "PSAttack.Modules." ascii
		$s3 = "PSAttack.PSAttackProcessing" fullword ascii
		$s4 = "PSAttack.Modules.key.txt" fullword wide

	condition:
		( uint16(0)==0x5a4d and ($x1 or 2 of ($s*))) or 3 of them
}
