import "pe"

rule SIGNATURE_BASE_Angry_IP_Scanner_V2_08_Ipscan
{
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "5fbcbb95-6cd4-5587-bf44-5b5ed133ce5e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L448-L460"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "70cf2c09776a29c3e837cb79d291514a"
		logic_hash = "1b50856ad35c146a684298a86f1629c45996ab08ffae8486a388805262ec2367"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "_H/EnumDisplay/"
		$s5 = "ECTED.MSVCRT0x"
		$s8 = "NotSupported7"

	condition:
		all of them
}
