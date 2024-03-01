import "pe"

rule SIGNATURE_BASE_Disclosed_0Day_Pocs_Shellcodegenerator : FILE
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		author = "Florian Roth (Nextron Systems)"
		id = "49250cbe-7bbd-5462-9324-1a8f350386f3"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "Disclosed 0day Repos"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3804-L3817"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b267a816871c30e9403805b942be25ed8e28ad2fd946f234f6877a65420754d8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"

	strings:
		$x1 = "\\Release\\shellcodegenerator.pdb" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and all of them )
}
