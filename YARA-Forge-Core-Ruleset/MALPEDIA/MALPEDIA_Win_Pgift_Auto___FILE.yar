rule MALPEDIA_Win_Pgift_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "77b72e7a-f170-5cb6-9a32-dd868251e29f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pgift"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pgift_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "5fec76c05b43d836fa9681344d4e2173c2fdd272e3aa573e02794115bc07ca47"
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
		$sequence_0 = { 53 ff7508 e8???????? 83450804 83c304 }
		$sequence_1 = { 2bc8 c1f902 7454 50 8d4de8 }
		$sequence_2 = { 50 0fb745d4 50 8d45ec ff760c }
		$sequence_3 = { 8d4df0 c645fc02 e8???????? ff750c }
		$sequence_4 = { 83f8ff 741e 53 50 8d4de8 e8???????? ff75e8 }
		$sequence_5 = { 8d4df0 ff3498 e8???????? 83f8ff }
		$sequence_6 = { 33db 8d4dec 895dfc e8???????? 8d8dd0feffff 895de8 e8???????? }
		$sequence_7 = { c645fc03 897e38 897e34 897e30 e8???????? 3bc7 }
		$sequence_8 = { ff7634 53 50 e8???????? 83c40c 8d4638 }
		$sequence_9 = { 8d4de8 e8???????? 6a5c 8d4de8 c645fc01 }

	condition:
		7 of them and filesize <98304
}