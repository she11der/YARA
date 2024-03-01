rule SIGNATURE_BASE_SUSP_Archive_Phishing_Attachment_Characteristics_Jun22_1 : FILE
{
	meta:
		description = "Detects characteristics of suspicious file names or double extensions often found in phishing mail attachments"
		author = "Florian Roth (Nextron Systems)"
		id = "3cb8c371-f40b-5773-84d1-3bce37da529e"
		date = "2022-06-29"
		modified = "2023-12-05"
		reference = "https://twitter.com/0xtoxin/status/1540524891623014400?s=12&t=IQ0OgChk8tAIdTHaPxh0Vg"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_phish_attachments.yar#L43-L141"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "647044fa3b5cf6f0e9e738fa7b7d24f8918b7a7fb359342e1314d97b50debf87"
		score = 65
		quality = 60
		tags = "FILE"
		hash1 = "caaa5c5733fca95804fffe70af82ee505a8ca2991e4cc05bc97a022e5f5b331c"
		hash2 = "a746d8c41609a70ce10bc69d459f9abb42957cc9626f2e83810c1af412cb8729"

	strings:
		$sa01 = "INVOICE.exePK" ascii
		$sa02 = "PAYMENT.exePK" ascii
		$sa03 = "REQUEST.exePK" ascii
		$sa04 = "ORDER.exePK" ascii
		$sa05 = "invoice.exePK" ascii
		$sa06 = "payment.exePK" ascii
		$sa07 = "_request.exePK" ascii
		$sa08 = "_order.exePK" ascii
		$sa09 = "-request.exePK" ascii
		$sa10 = "-order.exePK" ascii
		$sa11 = " request.exePK" ascii
		$sa12 = " order.exePK" ascii
		$sa14 = ".doc.exePK" ascii
		$sa15 = ".docx.exePK" ascii
		$sa16 = ".xls.exePK" ascii
		$sa17 = ".xlsx.exePK" ascii
		$sa18 = ".pdf.exePK" ascii
		$sa19 = ".ppt.exePK" ascii
		$sa20 = ".pptx.exePK" ascii
		$sa21 = ".rtf.exePK" ascii
		$sa22 = ".txt.exePK" ascii
		$sb01 = "SU5WT0lDRS5leGVQS"
		$sb02 = "lOVk9JQ0UuZXhlUE"
		$sb03 = "JTlZPSUNFLmV4ZVBL"
		$sb04 = "UEFZTUVOVC5leGVQS"
		$sb05 = "BBWU1FTlQuZXhlUE"
		$sb06 = "QQVlNRU5ULmV4ZVBL"
		$sb07 = "UkVRVUVTVC5leGVQS"
		$sb08 = "JFUVVFU1QuZXhlUE"
		$sb09 = "SRVFVRVNULmV4ZVBL"
		$sb10 = "T1JERVIuZXhlUE"
		$sb11 = "9SREVSLmV4ZVBL"
		$sb12 = "PUkRFUi5leGVQS"
		$sb13 = "aW52b2ljZS5leGVQS"
		$sb14 = "ludm9pY2UuZXhlUE"
		$sb15 = "pbnZvaWNlLmV4ZVBL"
		$sb16 = "cGF5bWVudC5leGVQS"
		$sb17 = "BheW1lbnQuZXhlUE"
		$sb18 = "wYXltZW50LmV4ZVBL"
		$sb19 = "X3JlcXVlc3QuZXhlUE"
		$sb20 = "9yZXF1ZXN0LmV4ZVBL"
		$sb21 = "fcmVxdWVzdC5leGVQS"
		$sb22 = "X29yZGVyLmV4ZVBL"
		$sb23 = "9vcmRlci5leGVQS"
		$sb24 = "fb3JkZXIuZXhlUE"
		$sb25 = "LXJlcXVlc3QuZXhlUE"
		$sb26 = "1yZXF1ZXN0LmV4ZVBL"
		$sb27 = "tcmVxdWVzdC5leGVQS"
		$sb28 = "LW9yZGVyLmV4ZVBL"
		$sb29 = "1vcmRlci5leGVQS"
		$sb30 = "tb3JkZXIuZXhlUE"
		$sb31 = "IHJlcXVlc3QuZXhlUE"
		$sb32 = "ByZXF1ZXN0LmV4ZVBL"
		$sb33 = "gcmVxdWVzdC5leGVQS"
		$sb34 = "IG9yZGVyLmV4ZVBL"
		$sb35 = "BvcmRlci5leGVQS"
		$sb36 = "gb3JkZXIuZXhlUE"
		$sb37 = "LmRvYy5leGVQS"
		$sb38 = "5kb2MuZXhlUE"
		$sb39 = "uZG9jLmV4ZVBL"
		$sb40 = "LmRvY3guZXhlUE"
		$sb41 = "5kb2N4LmV4ZVBL"
		$sb42 = "uZG9jeC5leGVQS"
		$sb43 = "Lnhscy5leGVQS"
		$sb44 = "54bHMuZXhlUE"
		$sb45 = "ueGxzLmV4ZVBL"
		$sb46 = "Lnhsc3guZXhlUE"
		$sb47 = "54bHN4LmV4ZVBL"
		$sb48 = "ueGxzeC5leGVQS"
		$sb49 = "LnBkZi5leGVQS"
		$sb50 = "5wZGYuZXhlUE"
		$sb51 = "ucGRmLmV4ZVBL"
		$sb52 = "LnBwdC5leGVQS"
		$sb53 = "5wcHQuZXhlUE"
		$sb54 = "ucHB0LmV4ZVBL"
		$sb55 = "LnBwdHguZXhlUE"
		$sb56 = "5wcHR4LmV4ZVBL"
		$sb57 = "ucHB0eC5leGVQS"
		$sb58 = "LnJ0Zi5leGVQS"
		$sb59 = "5ydGYuZXhlUE"
		$sb60 = "ucnRmLmV4ZVBL"
		$sb61 = "LnR4dC5leGVQS"
		$sb62 = "50eHQuZXhlUE"
		$sb63 = "udHh0LmV4ZVBL"

	condition:
		uint16(0)==0x4b50 and 1 of ($sa*) or 1 of ($sb*)
}
