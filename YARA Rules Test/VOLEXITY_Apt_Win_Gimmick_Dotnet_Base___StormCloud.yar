rule VOLEXITY_Apt_Win_Gimmick_Dotnet_Base___StormCloud
{
	meta:
		description = "Detects the base version of GIMMICK in .NET."
		author = "threatintel@volexity.com"
		id = "8723253f-ad11-509e-a9b4-f2c3258f9b5c"
		date = "2020-03-16"
		modified = "2022-03-22"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2022/2022-03-22 GIMMICK/indicators/yara.yar#L52-L76"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "0dd2aab308b7057d3075c792339af89d7ff9d617f1beb78ecdb725554defa5dc"
		score = 75
		quality = 80
		tags = ""
		hash1 = "b554bfe4c2da7d0ac42d1b4f28f4aae854331fd6d2b3af22af961f6919740234"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 1

	strings:
		$other1 = "srcStr is null" wide
		$other2 = "srcBs is null " wide
		$other3 = "Key cannot be null" wide
		$other4 = "Faild to get target constructor, targetType=" wide
		$other5 = "hexMoudule(public key) cannot be null or empty." wide
		$other6 = "https://oauth2.googleapis.com/token" wide
		$magic1 = "TWljcm9zb2Z0IUAjJCVeJiooKQ==" ascii wide
		$magic2 = "DAE47700E8CF3DAB0@" ascii wide

	condition:
		5 of ($other*) or any of ($magic*)
}