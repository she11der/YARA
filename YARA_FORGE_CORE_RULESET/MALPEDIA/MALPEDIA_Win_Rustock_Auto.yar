rule MALPEDIA_Win_Rustock_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "cb44bdc8-a730-56ac-98ad-0553c4475f0d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rustock"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rustock_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "5fff7e7d2c26e2013c1d3a65535e3ac75dc9cd45cc7a0c04309e438d2a86951e"
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
		$sequence_0 = { 8d6424fc 892c24 31ed 01e5 8d6424e4 50 }
		$sequence_1 = { 031d???????? 21db 5e 5a }
		$sequence_2 = { 8bd8 85db 7439 8b4dc0 33c0 8bfb 8bd1 }
		$sequence_3 = { 83c604 56 53 ff15???????? 53 }
		$sequence_4 = { 833d????????00 7421 56 e8???????? 85c0 59 75ac }
		$sequence_5 = { 50 ff7520 e8???????? 83c418 8945cc 3bc7 74d4 }
		$sequence_6 = { ff750c e8???????? 68e8030000 ff15???????? e8???????? 8bf8 }
		$sequence_7 = { 59 8945c4 83f8ff 7507 33c0 e9???????? 3b4520 }
		$sequence_8 = { ebb5 7402 ebd3 8b1c24 68???????? }
		$sequence_9 = { 014514 a1???????? 83f802 0f84de010000 3bc7 }

	condition:
		7 of them and filesize <565248
}
