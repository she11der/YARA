rule SIGNATURE_BASE_Invoke_Osiris
{
	meta:
		description = "Osiris Device Guard Bypass - file Invoke-OSiRis.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "b9f4e5dd-2366-5898-9f46-17584139469f"
		date = "2017-03-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_ps_osiris.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c63402fe46cec3f452eb740b1b8b22475535ce867d6268d4834b46f879ff7306"
		score = 75
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "19e4a8b07f85c3d4c396d0c4e839495c9fba9405c06a631d57af588032d2416e"

	strings:
		$x1 = "$null = Iwmi Win32_Process -EnableA -Impers 3 -AuthenPacketprivacy -Name Create -Arg $ObfusK -Computer $Target" fullword ascii
		$x2 = "Invoke-OSiRis" ascii
		$x3 = "-Arg@{Name=$VarName;VariableValue=$OSiRis;UserName=$env:Username}" fullword ascii
		$x4 = "Device Guard Bypass Command Execution" fullword ascii
		$x5 = "-Put Payload in Win32_OSRecoveryConfiguration DebugFilePath" fullword ascii
		$x6 = "$null = Iwmi Win32_Process -EnableA -Impers 3 -AuthenPacketprivacy -Name Create" fullword ascii

	condition:
		1 of them
}
