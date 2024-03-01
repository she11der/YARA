import "pe"

rule ARKBIRD_SOLG_APT28_Zekapab_June_2020_1 : FILE
{
	meta:
		description = "Detect Delphi variant of Zekapab"
		author = "Arkbird_SOLG"
		id = "cf87e67f-2db9-537d-8800-8cd47b47c276"
		date = "2020-06-28"
		modified = "2020-06-28"
		reference = "https://twitter.com/DrunkBinary/status/1276573779037163520"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-28/APT28_Zekapab_June_2020_1.yar#L3-L29"
		license_url = "N/A"
		logic_hash = "a02a78b8f60cf9d4441cc18b70fd00ec89253a5feafdc0eb392486b575bc61e2"
		score = 75
		quality = 25
		tags = "FILE"
		hash1 = "12879b9d8ae046ca2f2ebcc7b1948afc44e6e654b7f4746e7a5243267cfd7c46"

	strings:
		$s1 = "54484520494E535452554354494F4E2041542030783763663538326164205245464552454E434544204D454D4F525920415420307830303030303030302E2054" ascii
		$s2 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
		$s3 = "5C4164646974696F6E735C73616D636C69656E742E657865" ascii
		$s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii
		$s5 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii
		$s6 = "Software\\Borland\\Delphi\\Locales" fullword ascii
		$s7 = "SOFTWARE\\Borland\\Delphi\\RTL" fullword ascii
		$s8 = "Software\\Borland\\Locales" fullword ascii
		$s9 = "FastMM Borland Edition" fullword ascii
		$s10 = "#7@Qhq\\1@NWgyxeH\\_bpdgc" fullword ascii
		$s11 = "4150504C49434154494F4E204552524F52" ascii
		$s12 = "436D442E457865202F6320" ascii
		$s13 = "6572726F72" ascii
		$s14 = "WndProcPtr" fullword ascii
		$s15 = "Request.UserAgent" fullword ascii
		$s16 = "ProxyPassword<" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="dbdfe8b60c1de0a9201044b3e91b9502" or 12 of them )
}
