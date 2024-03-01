import "pe"

rule SIGNATURE_BASE_Hacktool_MSIL_SEATBELT_1_1 : FILE
{
	meta:
		description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
		author = "FireEye"
		id = "cfd730ac-1eec-5e04-b871-c14912bc0425"
		date = "2020-12-08"
		modified = "2023-01-27"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_fireeye_redteam_tools.yar#L1210-L1233"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "848837b83865f3854801be1f25cb9f4d"
		logic_hash = "89275ec08b75cef371b70fb749cbcada3f30309869094ab7940811fe40f8a008"
		score = 75
		quality = 67
		tags = "FILE"

	strings:
		$msil = "_CorExeMain" ascii wide
		$str1 = "{ Process = {0}, Path = {1}, CommandLine = {2} }" ascii nocase wide
		$str2 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii nocase wide
		$str3 = "LogonId=\"(\\d+)\"" ascii nocase wide
		$str4 = "{0}.{1}.{2}.{3}" ascii nocase wide
		$str5 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii nocase wide
		$str6 = "*[System/EventID={0}]" ascii nocase wide
		$str7 = "*[System[TimeCreated[@SystemTime >= '{" ascii nocase wide
		$str8 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii nocase wide
		$str10 = "{0,-23}" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $msil and all of ($str*)
}
