rule MALPEDIA_Win_Compfun_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b70b97d4-0cf0-525a-92ea-8899bccf1319"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.compfun"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.compfun_auto.yar#L1-L161"
		license_url = "N/A"
		logic_hash = "a0b696c7a840205849cf5ac2e95df1021718fd8d1c1053a2c6b648baa042ec58"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8d857cfeffff 50 8d857cffffff 50 e8???????? 59 50 }
		$sequence_1 = { c7460c65726174 c746106f722063 c746146c617373 c6461800 8bc6 5e }
		$sequence_2 = { 56 e8???????? 83c40c c74608697a6520 c70647657446 c74604696c6553 c6460b00 }
		$sequence_3 = { c7460472656174 c7460865557365 c7460c72546872 c6461300 }
		$sequence_4 = { e8???????? 83c40c c7460c33322020 c706496e7072 }
		$sequence_5 = { 6880000000 6a00 56 e8???????? 83c40c c70647657446 c74604756c6c50 }
		$sequence_6 = { c6460f00 8bc6 5e 5d c3 55 }
		$sequence_7 = { c7460825202020 c70625415050 c7460444415441 c6460900 8bc6 5e }
		$sequence_8 = { 034c2460 488b442450 894820 488b4c2450 }
		$sequence_9 = { 03c1 4863d0 488b4c2430 488b442438 }
		$sequence_10 = { 03c1 89442420 8b442420 83c001 }
		$sequence_11 = { 03c1 89442420 8b4c2438 488b442450 }
		$sequence_12 = { 03c1 89442420 8b542438 486bd218 }
		$sequence_13 = { 034c242c 488b442470 894820 488d542440 }
		$sequence_14 = { 03c1 89442434 8b442430 39442434 }
		$sequence_15 = { 0344242c 8bc8 e8???????? 4889442448 }

	condition:
		7 of them and filesize <402432
}
