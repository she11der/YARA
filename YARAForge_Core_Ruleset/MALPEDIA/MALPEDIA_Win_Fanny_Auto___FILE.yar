rule MALPEDIA_Win_Fanny_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "cd0c75da-8b4c-5363-98ec-15a67064033c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fanny"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.fanny_auto.yar#L1-L171"
		license_url = "N/A"
		logic_hash = "415f51a7b92a8dd2e587e9f69b01a611a89ad0fc5dace80d2d81091a3ef0d182"
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
		$sequence_0 = { 8b45c0 85c0 7422 8935???????? 6a00 }
		$sequence_1 = { 8955d0 0fb645cf 3de9000000 7423 0fb64dcf }
		$sequence_2 = { 8b4dfc 8b11 52 ff15???????? 85c0 7502 }
		$sequence_3 = { 53 ff15???????? 8bf0 83c420 85f6 0f846a010000 }
		$sequence_4 = { 8b450c 8945d4 c745c400000000 8b4dc4 3b4dd0 7d26 6a00 }
		$sequence_5 = { 53 ff15???????? 8bf0 85f6 7420 6a03 }
		$sequence_6 = { eb05 1bc0 83d8ff 85c0 7517 8b842418010000 }
		$sequence_7 = { eb57 8b450c 8a4dd0 88481f 8b55d0 52 8b4510 }
		$sequence_8 = { 8b4dfc c7410c00000000 ff15???????? 8b55fc }
		$sequence_9 = { 53 ff15???????? be00000200 56 }
		$sequence_10 = { 5b c9 c3 80a5dcfeffff00 }
		$sequence_11 = { 50 e8???????? 83c424 eb03 8b7508 }
		$sequence_12 = { 53 ff15???????? 8d85e8fdffff 50 ff15???????? }
		$sequence_13 = { 6800400000 6a00 ff15???????? 897c2410 56 }
		$sequence_14 = { 53 ff15???????? 8bf0 59 85f6 0f84e9000000 8a4508 }
		$sequence_15 = { 33c0 83e103 f3a4 8b13 8b4d00 85d2 760e }

	condition:
		7 of them and filesize <368640
}