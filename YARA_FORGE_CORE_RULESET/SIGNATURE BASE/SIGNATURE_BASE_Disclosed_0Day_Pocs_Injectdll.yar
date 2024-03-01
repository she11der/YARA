import "pe"

rule SIGNATURE_BASE_Disclosed_0Day_Pocs_Injectdll : FILE
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		author = "Florian Roth (Nextron Systems)"
		id = "90a4dca0-4f12-5946-9d5d-0b93bb5a3c5d"
		date = "2017-07-07"
		modified = "2022-12-21"
		reference = "Disclosed 0day Repos"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L3727-L3745"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b0a9bd4fa2d8a1192258b303cb757c8bbce7f6962a1d895f57add8a1c3887799"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "173d3f78c9269f44d069afbd04a692f5ae42d5fdc9f44f074599ec91e8a29aa2"

	strings:
		$x1 = "\\Release\\InjectDll.pdb" ascii
		$x2 = "Specify -l to list all IE processes running in the current session" fullword ascii
		$x3 = "Usage: InjectDll -l|pid PathToDll" fullword ascii
		$x4 = "Injecting DLL: %ls into PID: %d" fullword ascii
		$x5 = "Error adjusting privilege %d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
