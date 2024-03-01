rule MALPEDIA_Win_Kleptoparasite_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d0389ad4-24e3-5ce2-885f-8e2d3c44dd15"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kleptoparasite_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.kleptoparasite_stealer_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "1caf749c6c15dea159c6ab2428d269f9b9674545b72666548fcdc2b3e50e89c9"
		score = 60
		quality = 35
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
		$sequence_0 = { 7405 8901 895104 8be5 5d c3 3b0d???????? }
		$sequence_1 = { ebe4 6a0c 68???????? e8???????? 8365e400 33c0 8b7d08 }
		$sequence_2 = { e8???????? cc 55 8bec 56 e8???????? 8b7508 }
		$sequence_3 = { 895104 8be5 5d c3 3b0d???????? 7502 }
		$sequence_4 = { b8???????? c3 e9???????? 55 8bec 56 e8???????? }
		$sequence_5 = { 59 c3 6a10 68???????? e8???????? 33ff 897de0 }
		$sequence_6 = { 895104 8be5 5d c3 3b0d???????? }
		$sequence_7 = { cc 55 8bec 56 e8???????? 8b7508 6a02 }
		$sequence_8 = { 8901 895104 8be5 5d c3 3b0d???????? 7502 }
		$sequence_9 = { c3 e9???????? 55 8bec 56 e8???????? 8bf0 }

	condition:
		7 of them and filesize <3006464
}