rule SIGNATURE_BASE_Opcloudhopper_Dropper_1___FILE
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		author = "Florian Roth (Nextron Systems)"
		id = "b43ffb7e-1643-5560-8719-9c63582920e7"
		date = "2017-04-03"
		modified = "2023-12-05"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_cloudhopper.yar#L81-L94"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ee0caf8a08db9a2a83f10178e2ee890b6b0bc6e699ebb3d01fa94fa48c6dfdee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "411571368804578826b8f24f323617f51b068809b1c769291b21125860dc3f4e"

	strings:
		$s1 = "{\\version2}{\\edmins0}{\\nofpages1}{\\nofwords11}{\\nofchars69}{\\*\\company google}{\\nofcharsws79}{\\vern24611}{\\*\\password" ascii

	condition:
		( uint16(0)==0x5c7b and filesize <700KB and all of them )
}