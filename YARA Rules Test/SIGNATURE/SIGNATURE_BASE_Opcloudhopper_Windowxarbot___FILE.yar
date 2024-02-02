rule SIGNATURE_BASE_Opcloudhopper_Windowxarbot___FILE
{
	meta:
		description = "Malware related to Operation Cloud Hopper"
		author = "Florian Roth (Nextron Systems)"
		id = "4434632a-1886-5e8b-a205-12220263980a"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_cloudhopper.yar#L267-L279"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "5d8a9c25032c5371e843f8e80884e43a64c73b1644605b39b2dff11104c3bbcd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Release\\WindowXarbot.pdb" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}