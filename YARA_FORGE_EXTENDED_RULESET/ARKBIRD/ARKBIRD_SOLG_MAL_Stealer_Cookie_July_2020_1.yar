import "pe"

rule ARKBIRD_SOLG_MAL_Stealer_Cookie_July_2020_1 : FILE
{
	meta:
		description = "Detect strings used by EdgeCookiesView and ChromeCookiesView in the ressources of the Cookie Stealer"
		author = "Arkbird_SOLG"
		id = "02a68973-73b2-572a-a358-f0edc921773a"
		date = "2020-07-09"
		modified = "2020-07-09"
		reference = "https://twitter.com/JAMESWT_MHT/status/1281154921811841026"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-07-09/MAL_Stealer_Cookie_July_2020_1.yar#L3-L32"
		license_url = "N/A"
		logic_hash = "63747567a9dd68ac0d16b67910957cb9bc28d7237f431ac0c76403ca810e1b94"
		score = 75
		quality = 50
		tags = "FILE"
		hash1 = "47b2b56c961cdc78bf06eed30737232ba99424b51648418bacacd522a12ad339"

	strings:
		$x1 = "C:\\Users\\admin1\\AppData\\Local\\Temp\\samplebin.exe" fullword wide
		$x2 = "https://graph.facebook.com/v7.0/act_fb_uid?access_token=fb_access_token&_index=5&_reqName=adaccount&_reqSrc=AdsCMPaymentsAccount" ascii
		$x3 = "https://graph.facebook.com/v7.0/act_fb_uid?access_token=fb_access_token&_reqName=adaccount&_reqSrc=AdsCMPaymentsAccountDataDispa" ascii
		$x4 = "Cookie:" fullword ascii
		$x5 = "autoLoginCookie name=" fullword ascii
		$x6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36" fullword wide
		$s7 = "https://graph.facebook.com/v7.0/act_fb_uid?access_token=fb_access_token&_priority=HIGH&_reqName=adaccount&_reqSrc=AdsCMAccountSp" ascii
		$s8 = "https://www.facebook.com/login/device-based/login/" fullword wide
		$s9 = "api/?sid=" fullword wide
		$s10 = "/deleteregkey" fullword ascii
		$s11 = "Old cookies folder of Edge/IE" fullword ascii
		$s12 = "https://graph.facebook.com/v7.0/me/adaccounts?access_token=fb_access_token&_reqName=me%2Fadaccounts&_reqSrc=AdsTypeaheadDataMana" ascii
		$s13 = "https://graph.facebook.com/v7.0/me/adaccounts?access_token=fb_access_token&_reqName=me%2Fadaccounts&_reqSrc=AdsTypeaheadDataMana" ascii
		$s14 = "ChromeCookiesView.exe" fullword wide
		$s15 = "EdgeCookiesView.exe" fullword wide
		$s16 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
		$s17 = "login/device-based/login" fullword ascii
		$s18 = "c_user" fullword wide
		$s19 = "c:\\Projects\\VS2005\\EdgeCookiesView\\Release\\EdgeCookiesView.pdb" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2600KB and (pe.imphash()=="89c8a19cc2d9172de5901988530c700d" or ((3 of ($x*)) and (8 of ($s*))))
}
