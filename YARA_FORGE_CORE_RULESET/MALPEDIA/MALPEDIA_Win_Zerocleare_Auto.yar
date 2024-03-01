rule MALPEDIA_Win_Zerocleare_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3657cdfc-db20-5908-b80b-f3809b1ef7a0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zerocleare"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.zerocleare_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "684e088a58b2073463dab14cb1ba7b141fc0ac01570965634aebae02ef8b6f64"
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
		$sequence_0 = { db2d???????? b801000000 833d????????00 0f854f6efeff ba05000000 8d0df0694400 e8???????? }
		$sequence_1 = { 0f1185d8f7ffff f30f7e4010 660fd685e8f7ffff c7401000000000 c7401407000000 668908 c645fc04 }
		$sequence_2 = { 6a00 8d45e8 50 6a18 }
		$sequence_3 = { ffd6 6af4 898578f7ffff ffd6 }
		$sequence_4 = { 0f114598 0f1145a8 ff15???????? 8bf8 }
		$sequence_5 = { 895614 7410 c74620df494300 c74624f24a4300 eb0e c7462087414300 }
		$sequence_6 = { c745e4ad184200 eb08 8d4dd8 e8???????? 837e1808 74f2 8bce }
		$sequence_7 = { 660f58ca 660f2815???????? f20f59db 660f282d???????? 660f59f5 660f28aa70534400 660f54e5 }
		$sequence_8 = { 8b04cdd40a4400 5f 5e 5b 8be5 5d c3 }
		$sequence_9 = { 33c0 8985e4f7ffff 90 8b4c3814 8d1438 8d4101 }

	condition:
		7 of them and filesize <42670080
}