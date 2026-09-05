//! Wire-format tests against bytes the reference implementation produced.
//!
//! # Provenance
//!
//! The two `.par3` index files embedded below were created by the official
//! `par3cmdline` at commit `2971702e501f1350b1c7b9d11369af9157d6ed56`, built and
//! run inside a Debian bookworm container on native linux/arm64 (no emulation).
//! The build used the project's own CMake setup:
//!
//! ```text
//! cmake -D CMAKE_BUILD_TYPE=Release -G Ninja -S src -B build-linux
//! cmake --build build-linux
//! ```
//!
//! with two source changes needed only to compile on arm64: the bundled BLAKE3
//! was restricted to its portable backend, and the bundled Leopard codec was
//! given an `sse2neon` shim. Neither affects the bytes of an index file.
//!
//! The archives were then created with:
//!
//! ```text
//! par3 create -B<in> -s2000 -c2 -R -v -C"rarpar oracle" set.par3 a.bin b.txt sub
//! par3 create -B<in16> -s100 -c3 -v -C"rarpar oracle gf16" set16.par3 big.bin
//! ```
//!
//! The input files are regenerated here from the formulas they were made with,
//! rather than embedded, and every damage case flips bytes of those regenerated
//! inputs in memory. No PAR3 bytes in this file were assembled or edited by
//! hand: they are exactly what the reference implementation wrote.
//!
//! The recovery volumes are deliberately not embedded. They carry only Recovery
//! Data packets, which this crate parses but computes nothing from.

use par3_rs::packet::{
    BlockChecksum, CauchyMatrixPacket, ChunkDescription, ChunkTail, DirectoryPacket, FilePacket,
    GaloisField, StartPacket,
};
use par3_rs::{
    FileVerdict, InputSetId, Packet, PacketBody, PacketType, Par3Set, ParseContext, fingerprint,
    scan_packets, verify_file,
};

/// `set.par3`, the 1050-byte index of the GF(2^8) oracle archive: block size
/// 2000, 5 input blocks, 11 packets, InputSetID `24a1ad601ae5bc72`.
const SET_PAR3_HEX: &str = concat!(
    "5041523300504b545038f265c2545838b57dc380a621d077730000000000000024a1ad601ae5",
    "bc72504152204352450070617233636d646c696e652076657273696f6e20302e302e310a2868",
    "747470733a2f2f6769746875622e636f6d2f50617263686976652f70617233636d646c696e65",
    "295041523300504b5400e35e170bf5f6f81adca2c72d7bc24a520000000000000024a1ad601a",
    "e5bc725041522053544100000000000000000000000000000000000000000000000000d00700",
    "0000000000011d5041523300504b5418e304ab773d2ef7d07013af9c525d6448000000000000",
    "0024a1ad601ae5bc725041522043415500000000000000000000000000000000000000000000",
    "0000005041523300504b54a4e15fb479a1e1f521b044c6ed80298f880000000000000024a1ad",
    "601ae5bc725041522046494c000500612e62696e9fb4900f58cde15899dac71e48bb629da58f",
    "e862e286769a008813000000000000000000000000000054a4102520efece5f3063319a1db19",
    "e6d7c5f610c95faaf1020000000000000000000000000000005041523300504b54df6b312f7c",
    "c0132c31aec3392d1df1d0620000000000000024a1ad601ae5bc725041522046494c00050062",
    "2e7478747cc819ab3a250470bc094a8703d2ce996403c13225b97a81000a0000000000000071",
    "72737475767778797a5041523300504b54b1ff9d1bd6e2bacba5f222636569b1ab6000000000",
    "00000024a1ad601ae5bc725041522046494c000500632e62696e43a6dca1462e8d9fde50e340",
    "37f9dac160cf99f04c560b9a00a00f00000000000003000000000000005041523300504b5475",
    "213e39403b65ce64b8a4482050107d490000000000000024a1ad601ae5bc7250415220444952",
    "00030073756200000000b1ff9d1bd6e2bacba5f222636569b1ab5041523300504b54567ee9a6",
    "097f746011ed7af8c87159726d0000000000000024a1ad601ae5bc7250415220524f4f000500",
    "000000000000000000000075213e39403b65ce64b8a4482050107da4e15fb479a1e1f521b044",
    "c6ed80298fdf6b312f7cc0132c31aec3392d1df1d05041523300504b54a2e64b504206b82c41",
    "518e10cd857395680000000000000024a1ad601ae5bc72504152204558540000000000000000",
    "0033d538987da474bd7a69a420d440f3001f6ce7d69dcb6f4f5ff17a09eb891cfae1ae7a5f18",
    "205d4045c943f448e0bd0a5041523300504b54395ef088ac8103375fa140351588c045680000",
    "000000000024a1ad601ae5bc72504152204558540003000000000000007b3acd21f70ad67f61",
    "75377ebff7f079c5c1ba5279a9108ade7d75b410e74756eccf31d471bf6b1ec77d4f3733be89",
    "df5041523300504b54a096752369cc71ebd6cc4dc0e8ef53b63d0000000000000024a1ad601a",
    "e5bc7250415220434f4d00726172706172206f7261636c65"
);

/// `set16.par3`, the 7807-byte index of the GF(2^16) oracle archive: block size
/// 100, 301 input blocks, 7 packets, InputSetID `b49d55b4c53f292c`.
const SET16_PAR3_HEX: &str = concat!(
    "5041523300504b546f98027a18441dba6da6fccefaa3e2a77300000000000000b49d55b4c53f",
    "292c504152204352450070617233636d646c696e652076657273696f6e20302e302e310a2868",
    "747470733a2f2f6769746875622e636f6d2f50617263686976652f70617233636d646c696e65",
    "295041523300504b5488c7c93f7dd04b3d53017059c5233b3a5300000000000000b49d55b4c5",
    "3f292c5041522053544100000000000000000000000000000000000000000000000000640000",
    "0000000000020b105041523300504b54ef6521cefa29fee8e095add446e49cdb480000000000",
    "0000b49d55b4c53f292c50415220434155000000000000000000000000000000000000000000",
    "000000005041523300504b542f8705b1633e40f4ed7f134954f24e4c8a00000000000000b49d",
    "55b4c53f292c5041522046494c0007006269672e62696ebc072daa7256701b46ef7bc5a5bfd9",
    "52597ce19fcb4d1d3a0062750000000000000000000000000000839491210c57e6991f15ccec",
    "ac0b07ee0e69b068878786a42c0100000000000000000000000000005041523300504b546534",
    "74c72a554c697bd5d9bb3fec1a174d00000000000000b49d55b4c53f292c50415220524f4f00",
    "2d0100000000000000000000002f8705b1633e40f4ed7f134954f24e4c5041523300504b54f0",
    "56c7449505b6691f00207948ae6de6581c000000000000b49d55b4c53f292c50415220455854",
    "000000000000000000e529aad6a2641dcf68ea04c3f33dd559656ccbae64c69354ef534c1159",
    "cd124f5713bd5f24961845e5cfd36229165b1b78d11b53f2e774d476352f8cc80c2dd66c49ac",
    "646a87cf22317f42bea5dcbb4df6a536f1983345b173eb2d441c3b3cae6adb89710ce679a9d8",
    "9eee39238bfca80d664760009a26bc04310c387305d48b22b7fd3544f9bf77029c8002db7f69",
    "67679e061e93504c2a42e97e29dab7576b3882ffc0c64c2e93f86fad606e9eb95679ef840f15",
    "37e65ba855f859bad142d408ef513c914fc25bd628e687930eed4bc3f62d4f32df27fc2d712d",
    "ea1c287aac01bb4249e3c80700b1f18d643fb0d82759dd3dbd0fbe4b8dbac379e10677df4708",
    "f746b1af53280c4c04228c24554a89f428515aade56b567d5065b2226328586a25c1327e1932",
    "417009332dcda89d5e5442f1b8e473cf3c05130ac3b9bc27a504f7ccdd5e88eca0f4fbae4382",
    "378f6d8e099911c41d788c6343bcfd843293b51098b44e6002e9728e40ef8302f45adcd26d88",
    "d64bf1cf569d3730bf86e7ee44f2d4a61fcc8b2f6f0046307755f54628400182d0a967e1a8ac",
    "c324d70628b267e1f6b9637404cc54879f4ea4049a99c7cd066f4866475badb57b46412ec57d",
    "0abb07b875ef0f9e6f41d82b47ad91a2cc8f719df78f9007ef323ee6a8a47d990eaefe88e202",
    "7dc2a54554909bf6bf8b1049737437e2bef147cf4dba1410542f1705c3f7a9c9236c58545ea6",
    "dc0cf6d8fd6f285f8ec59d7a48643c6c8a564de06affaa9f95c3850cf70a2667e8f851d0204a",
    "cda01bdba26030fe0e7e82063b5b21c1e3e6ed53dbaf1122da840385caed22409f7360408f89",
    "3d618e2e2c3e3a65228c13f4fc6d7a56c87da07de4ec9305e4b27a815b032d69f1a2e7de6f46",
    "588a9450fcd1e44094e5c2ff2534da2533d9c71d07d9961cb7705a6be1321e4189ad49a2a159",
    "b6907e689f024e3153675617ae8b6b85073d9707cb84382789e44ef4dd3a64d545b67c13ffab",
    "243ebdb66e5a232f255688eb9e055bf4170a7a632d42c96617666f74ffd06f22a144df054762",
    "201634699dd14e9ae0890fc57c11c4c90ae9ea9aea5df6542dc178a585558f85e6a803d78104",
    "0b4cf25d2ec2191ae16f5172087290b772e2d8ba8cb209e7987788170ddd6e0d5fb74460376e",
    "daf8f7a1f108d1e797afb266dc01804ebe6672ee886a567de5d27dd8131411a27f7a3b618100",
    "84808b30c96d6f9867055690a12957166a88583183a643adada0618a8f63f8aaddd704567215",
    "4c65bb12d14ac041b2d7e3889ed27cbb36c854baff534972fe3c6cf4591b296e339799cb5f91",
    "462fc58a98ae633278c9f1a6e4c97d35a5c04a042c61206bd88e9c3566666708fdbf1a08d783",
    "1e3d71ac2a01e24ad6c4bb51186ede5898890532f5164ce2dc12ead5e24177d5b5ee14f9e018",
    "6dda868ccdda2cc02563ac020f64f7cf9a603f9bafde04cd4115728bb0fa5116e28549dfd6af",
    "806165de3f9f4f1c33fb227af6920e50a9955b66e21ddc75433833f6ce58c083d52a2d610a0d",
    "540be24f53a549baabb125768cc6d9e60240153f7eb3508739257905f166a52af9f6f3163fe9",
    "2be6f6c03e5708cfc49be4c4a413c3c05672e13253712ab1af934935e1399160d3fc85b2d716",
    "f36499b67385162f0b53043aa341c27ee108c71443fb5bc682d6a2077aad61f0269345873bff",
    "ddc2920cfc61ffa420343604ea3b9c261245c14e737f743f9f90d6ab574c9ee49885a133cf00",
    "5378dbeeccf804162225bd1c226a9416e05c705608334b1c18c8fca38dbc48ba33b3ea7182f0",
    "5595fa1aa59363e0a8efea7a5760dd0fd16fd04ec5b5f3b354a1fe828784de45a7609d38a0bb",
    "0dbc5f8f970c50596e7b99eafd7bab0e2ddae3760682e0d55e3dc984c16c4d0a168da7842656",
    "90a5f083407040b8b916af6ccb2ae31bb3d7ada091562ae3b78c502de463a1f27e03675a50fc",
    "1f82ab231961d5ac41dc9b2dd3179e4427e29cf0d064858f7eed4af015a52c12f299c23104c1",
    "b81e3a8b1c100a0154848dc01ce36f3f3e2bc1353de3d168fa5aa1c3a09a8a53a7225b386eb9",
    "2f0d3feec54d401a776be17dd3484a3a8fe6830a3417c6b9ad14561b26b45ac1172afe3b843d",
    "581f81b8d2e43bc65019f984ff25d91ad8e2028851b94b06f709418e5a021ec4d12e9482b7a7",
    "d695762431c462f889e737033b689df9b7cb51480e248aaefc1a0b43868d82f140bb51e99002",
    "a72fe0d087fc0381a770dfad3e7554badeae59e5106600b749788f0bfb7396c24ddc88d35f40",
    "91151c71c324d73da47c86d1b5c91f8ab82e3f2abded621e288ae5024735be2e33c0f2d76f59",
    "74a4fd660a93c498c1a262cdbee6b32b7f8bf62292332a95343f0fc78cb7bb09c970712b3e94",
    "9f332b93800e6b4923189441556c998a5dd5b5dbc7d4fdbbee36c128bf063cb64ea00dbb1c3b",
    "9c879d5c2921db313ccc21b5990d217aea3b2918fa6f705ad5515ed8bb00dbbcffbce2f815f1",
    "0ad135af38ee2abb05dcd06ebd22253ed38012ee40d62da06c0600842f9397b75d8a01199d9a",
    "6946084cf0d41ea133519af2c4a31e96f2410fae30261636b7a9a120c8ddd14fa9526cff3464",
    "ef97137def8e0239ae9cf6e6e8fd60a6607b18d9766ce6194ec83a26905debd354fb03560426",
    "761d0c5d07a44267c9a4da5721a67c57494c29ccea5e9a053433a06e4a1ebc82936cf1f67108",
    "ad479b8fedbde0c8c126a15585c9594aa10a51ac58615f25bbbe672bffd46581cfdb926cc06c",
    "6961cee5c4883f461f993f0c98488cc913acffb803cd73a7baed10a1cb43e9bf7edef9e96ef8",
    "2ca78690013fcaef26465b301125099e77ad4537a43ead9824809e01aebdf6344f5bb340e307",
    "fb8cf22d9cba7573dac9d92273c0315c86c3ac1d03e086e261593b78c3e9516fab5057000ad8",
    "d173c2bda2feb6f835cdd6dfe003e0267f8252deb7086350d9747bc850836ef55a8a79b254c4",
    "32190990f2f9f5a28eb3fa020dfa4820e8284a3fc5a29c334928c8ccab30cc361dfcd4b25ff9",
    "a3b4643dd43cb49f8b6b7a20f359ac67e509d469f3088654099f8e708b8935b995db4c0ecea6",
    "9c04c681e7732f3f9f0a5cbd12a3c8d5d78b5f2133da7f95481572310f3ab8f98726164393c7",
    "aee9eaff934d1e7d1742da5642b67a872146f5463327c0eb34d36077c43b4f83ae7ff6ef4878",
    "f4e78d6799f3412510ad0ff93099e160ab3ec0627fc6869434efac32b87b01833e66442705c1",
    "5056a682d8dfb6ce6b65c055d52fdfd9ca5108affd029ffe3a04928aef5a9150eebd1b158434",
    "9527ef5bc323b4b1faecd0dc67c23072db40a6fd3240507a081eb71635e2eef5fd502a920112",
    "23c2fe46e194003a4e1893313b601f8f2a3d64ac6f6fe4dfae2f618bb631f5b73d2e07bc455e",
    "6c22031d8e16296173381289eb6858b709f92c39854bf91bb6363f471f3ca8cbef64a90295f3",
    "a4f51c26523095fb529f673b5141d37f3e32778a432eaa3a2a2ff28054c1e56608029ba8e4eb",
    "ece3c6f5085d10265ff1c93be3c554e15cd5e6bb1b50f17fe7b3561a70b412217725d67b01e6",
    "025f50b3abe7ed1064e08499f9b28883a982e28a987cfadd9b8e1d5e26251be3f42873514ef4",
    "26d0d9879e9a3f7616befac99465fd45868b613a75958b3ef31639557eb1056e41ba4921d12a",
    "d9ddc7d23712845204a115b3592facd86277c202cd15ab791945cce5b11fea917b75f4bee98c",
    "a0ccfc1998abd9168f7bd749ab472cdc1a911b8b56d27d8fc0f5498ee2e9247e70afe85880a7",
    "fefc126323f95ef78d6ff04a6a2749f072970cb3a6d110b22015b9ca35b1e22b149bbbf27412",
    "30487ac23d84ee4d266d0dd5f877ad0ffdf3b635a29e1cc91d22b44fef99656c355f6dcfff01",
    "25fe610286d475f1008cad879f754b9e6ead25bfdfcd3561cf6ed5bb3c1986768ade127db720",
    "e921cb747f8fe3f404b0a3c1cb3f4516781943912bf45b67190343001f8ad9eb9b65146c05c2",
    "70757f1db51119b8f02404b3dc7e945109581585532e9090a657a710412d1046cf2aee9d7863",
    "53442764f8f3783374705af89de688039ec0ca92c36597c86b47bc59fa5d0e50db627605cb28",
    "593f1ba00857fcc148e132341209cb126b50ba81745f767e646da4a0167190a2e91a0d5c18ee",
    "096106f0f8acf4d7aab3107268c0e4b78b7378ee3bbcc28bd86af5ddae02533b5abd2ece5deb",
    "bdac19048114d24430ab59a251579282a7beb2caa2d67c6fcac93f6c13695bb5215b6c969215",
    "4db0a9716ccca7f5b9c2ef5d008de92896902f053d789dc4dbdd924c9f95eb4a268180a408dc",
    "1090313df8e2cee391aff24b667939bd29e3fe76e0f2fbd2e27d47378204091838a0721750d0",
    "d0069a877f4f9d0148f36b8239a000534bb312c6e96ea929ce5fcc7cc68e809922ed2cd923e9",
    "ae0aa6e429097022f11b4b1781491766c832cbb26a2df8b20ac1694d13cb94f18d2dd113dd3c",
    "4ffa93174bc3a2f1e9261a365ac0821c24823d3ff5a79f678387f233294ef52ccbc860ecf128",
    "f72cf7732130b3b1abfb5eab8f09c1fec84d425791478fd539d98b769512013c2b27d2f1ee69",
    "f6d94c1b5aa711bbd32ae8a286723d577d512f54b19d2a88e4058cc374828fc705a78f1a71be",
    "308af5f2602a0a8846cf1dbf6802b606d905a24ee351f1dad25c5f4370ca1323c75465a7cf6a",
    "0f94d56a9465a0f8b4caad93d7ec3f17638fddcf673f2bcdf1b2f4892a3fec807c6b5529546d",
    "317b2d30a7dab37750d658ddc242dbf8499598c44a253440e447cffe59aa76b622955c56d8d1",
    "0985e8cab13c6ff62ec1311b48731adb38840e81d1599ea8145a0e67e8a6f4275cdf83adbfbe",
    "cac4e14c220341b274081f8289ebc3b1fcfdd42122b45c2e719e150d5fb51aec638ad7482a76",
    "cb8a5db3707659a03a7d51b8a256640d398da6c14828459f011da38e33557203189c02164ac3",
    "1fb5a201788547e39366603b8891e88d647333d4c97796e9d12fd7617560ff43700916e5a8ac",
    "231ef739b67a60dfdcea0b38e3179cf20c51a19d2a10d2202cea0c63e82ddba41fc7390f10b7",
    "f917968468c8751e4696d62034421c00cbdfc26ba925a4d2f72ff0b9a4621dbacc115ef22f53",
    "f55345837c306f671f1932aef5122e1d2c4606c50975a08a12de6822612d987f0b43a59cce85",
    "9dad8ffff3ac1fc74d864e18cf8a990a6e908e1d846bb4b88a092c81c631919d75e7340ad210",
    "3b1dd1a0d850dbde359e94b91ad52a6f1c83cd866a9506915287a62fcd0d5fb3592bd90842dc",
    "069f326246e02af1e5624940b386e72bc6cd665fe994000ecf1589adcfffa65f030d22aac681",
    "787a21ce95aac39f1c4d3505e2b2aa9a0e2d5967ef384069cffa700cc744b2d01d6d1f7cd95c",
    "fead89e9bd81b173326f2c313bd2f21c03e6105694f33699b4b00a4a899a777bf1144485ff8a",
    "015b14dd6c521bcca34483a9f0fdeb2fff35ed138acfdc95764caa05799f28527fd1060e7b50",
    "18d0945945655c1098cf6fee4e152afc5e8a548c86da351ec098d62a3e94bd59159592ed3857",
    "bbbd49f537996613295c0ce43b80f216fff43cb578577e592c91b7b7a742bc4dbd668c4dfd1b",
    "3e7aba8e729d870f8d81e25d408600362422513ff7d6d0c353351ace08de464cb71511b6c60b",
    "e1d771b6dbc12c8b4f38c069695dbd74b916891468278fa50d6c150e26f096d2f2964e3b4a1e",
    "bf3109fdf654beefdfd653f6eac8355199fcbff5b85e995e2aae6ad759fc46da9ae8d6708509",
    "2e1555376743a7657ed0c71be0a2e2dba2ca42b34c544ae9a6c19892bf3bb15c747e38a5e0a6",
    "02199563b536850dbcb39f82a318bcf4fd92f5276e8d11618d867394288fa0e70b6918c169c0",
    "d05cb4fbcb9ba3c7f425356af1243e45fb4e5de15643f52c3ba13adc7e7e4d300325e9177848",
    "6432c3a15e16c93194aab51abfd8a8195868875056e2a7cb7917f9aa17617550d7275f16f2b4",
    "1647798a2cf9bc9684724ae865cb79b97a0d62e63cd28a3eee98544a6d4424289b0d145bbfda",
    "724d330ffb5abcbdd28c66d749ed7a4811c94dd18e1b081435060e633a2d59dcd556daf19183",
    "db2f6f201b1d63793837f894f3ac21de38157a519fbcd0c797837eb64c29219f780539c298cd",
    "18a22c524cf69d7f80740e569d4b63e1a6c55ee70d47e3afae4d9b49e2aa19a450c780b6da09",
    "f699877ce32ff705aaa861fa20d032e451d30cc90fb283662c78744c426c30a9375ad7bd5bff",
    "d746c79183f10c1c596884f4fa52303bda3254bdf7c0f7d816b82d844bc797caa5f19c93fe63",
    "b66e3bc22b50458222f79c30cd77fcf942b9c49e7debad91048eb30013b4d9feffb857ab3797",
    "269c93b237b32bdd59ccc430782ae50bc971513281746412a9c16f03ee445e76908d50bad482",
    "12e705ec8505b52fe425d29d5c33791260a9537e98c7397969dac850b987efbe7600dcc30ddd",
    "76c3f65053817a8588e5d4440de15cf1ad1556161cf5853b53c177bed7360f29062470fa687a",
    "d309847c061c661342c0facef7e697629303f359a349c9735cc4100d2c0c9f0388ec572fbb76",
    "279fca67b2e483d0eb8571e2e043a70e726e61bb90dcbdaa818b43e3b3409a9baf609dd61b4d",
    "1f55d6a5ae12aa1e59a33d3851d23b513a5a8d618917d1c5e9464119da14708e329a6345d3e9",
    "33f7dbfb2a1a8cc7b5bfc6e384fbbaf035427266ea0e9d52fc94a135a08f0c7102129a01082d",
    "b970466045f9df097ad22d0017d302fb6c9a8f6d8637e27de38f03a5abf7a741bc502402b2a0",
    "9622c085567e34127c013502641d5cb282418a0d7041e26065f3210d6a23d6ee57aaea9675eb",
    "8c96e25d089e0ff68ed5f38d6dbe5280a9bf317ddfbd629631ad4c3f34ad431e72ceaeba7b74",
    "cfbcd6008947d77eb777100eb5cea0bb8095d9ef127d0887f984f20bfdea2db91eadc77a334f",
    "e386819bbda39c422447096f4b80e779ffc4bff2eee9bd3304d54b11937e74d572a862e79cfd",
    "d372d0792b6df5e36e313eca8fa6f8cf68c9fdc07575be472d978ab100cca52857e54f47e7ff",
    "3181c4010e286267f8dffcd384bd65971f0ca05b7cf72a6350b3125ff80e8d31c7c3e88fa666",
    "e5d1cf9e9a5ed295a002b35771a17e30a1217a4f36cba9ad3328aec4986020ce68cfb5284c06",
    "b41220a79992374f6b70ad3a95934ab46715f7cb67cdaafda797101930e2c56d996228ba4cec",
    "fff4e62069aa89ff02069384bed7aa42a08803b7e1ef137637267f32c64a565662676b0d8447",
    "e2a0698816461536a7e3c1889da23e2c615aaea62cfb2cd540205342eca6dc8102af5b90f0f8",
    "2e6bbb313f0ebfd8130944fd43f750b6147679b10569ba0443f5506f677e98bd937c6ae8ddf4",
    "218b032e4a7dc41731e35f12d46bfaa80b95f3d6cba58241a0ad1d9e7cd1501410ac5a7b443c",
    "c58905c7c2383d82bb3cb6652d1639ad820e1c36d01611bf94c151ac6b48f7658883881149da",
    "ce8426f9662ed9408fa3a094e6b72135964912b902991eac9f27010b97738fac79a4eb0c5476",
    "c2d7820f299352773bf77b62b36bc541075528c4623e14759e5136c4624d672f8ac17649856c",
    "251ee79a2d498803e3e88f806602d4678a01efe4432ac39649ab8016b4fb00533c2c3f2d0519",
    "e33d800dfd3d26e013dae8e601c4c7fe8934cc6c0b9a4ed8b97987b10773409ad01424aef867",
    "38c58b9ce90c008c54b57db11e4d428ea54cfbeee0ace2d4b6ad639408d8a62f1d185491f4f7",
    "0480324bfaf121a02cf074f2a920eb9e5d46c91b67c472d28a25b16e1547d82f33c63365b88c",
    "f5a90a3ceb99772bb191e4a5a7d63928d2e93e9b074e8d6d35b0e0a0b60ac2818e0d1c62d828",
    "e638b52e3cce6f3ed2de852e124071f2d715855d8c8da0378a3a068a95bbf07621bb3fe5f726",
    "b9b2428ae677232558fc2999cd0c12f8cc0d5cfd6ef470bbcdbb28b8ebc58da16279b27b63ad",
    "dab03d1f9ddf5a39c073a75e68f2e081037bc3b5b29cc51b5c4168a9a386524e565fd8073eda",
    "11468ce4257f900957e99e2b6906a1b64020ac27d730b8d77f85f330c450a1549121a334f772",
    "9383db33d4df3e9225148f8593ce66fbf822bb6ef3a9a1f2398441fa485a09888d9b708d5146",
    "f4e17c185748e5e7c7f3c68626a27e93bc10067fdb24ef2632aa863bdbe24bceacfb8491f552",
    "a98be0cf2bbf9a9977982d24f864465a25bdc7d1c79182d3db0244fd4ba59defff69b1ae2fd0",
    "3b901a08ff5c607900d50eedd91df9a7578f15f905b10f401c0d71d78ddc8fdc3f507122221e",
    "f6ad556d4a9d0720d44da431205be6791fa986f0e66de6d348fe82b8e556d13082eb1ec63593",
    "8dd913ca004dd1355708984d0c58a214440ac9c7c1188577f42c926455e1d7818b1db671e12e",
    "8909a084192dc266f016e98cab92529102b86c1e2d4ce380ff6a0f80e63b080ddfea413b7f81",
    "f81b177ad9cd23bcaa81d424a07f659cefa9b3670e3f9dcd6b3f29075b434595d6584bf55e3c",
    "ff89c5b96fedcd67f93b3e1d454a77a39ff00753b8d808cc148502df87ea302b1cd0528079cb",
    "685b6dd0869b1c5234cb745eb3e0e0d142e22c9f6dfe658a0aaa7c20b3afdf10eb69c4b546d2",
    "4b9675f20190f4430fb6078f727ee241d0c17db1cb00a286d63651a5554ce6967b0867558a3b",
    "e6208e78b4ed2238d8931822bb21ef09ef5d74148e5ff0dd21db277734caf62b872cb293499d",
    "5229eba91fa180c8728a63700d11af1a5d0692ffeefa292fd4259458c056b681dcd38e2736de",
    "36d04aa815a42bf369226505f55b5da469da7818418e0c1cd2cb7013eb9cea1b7ed8f72ea74e",
    "229deab4929d08f1efb1f0330bae90077b82838c149e30dff4bfb6d73d972e11ba29518856fc",
    "905d8bb8afb0f633e9532ef9f648cc3c50ec74dc2d1bcf9fedd1bef85784fb39aea24395b0b8",
    "4cc00c13a5a7209f96755369da41b90c5f1388af51567d9dd2bcda9ec21fd7233ec1dd4254ba",
    "b9e3dc16f265d1cf85088b096c78a1db04721d459fb973d2fb789a42c1ae7a5bd613f9f75353",
    "1a8b83391ad808f0b0c21723718f2e0d0184a535d814ed0956f34b3baedcfcdadcb75d311ab6",
    "a81f9e71f35aeedf1ccef3e6af2b8b471b542267f5e4b580132355e24fd1f44cceb352b9869b",
    "5c85485be6ac0cb8e09a24f67035d9d1bd3a5c75bb9bd6145459958d7f39f19549c658e42fa2",
    "d8ad2973c0bbc4ee65bab6808ad206985a927a340d8cda5757f33ef1087167736d5d7494a07a",
    "23f6bcfc0cf5081f16a23092fbba9711089aa7ee5f565978e3965425ef7bf13673252d1e25fe",
    "98dade63c65e3987d06db4edf7a7747074896d92290431d9d480c7f62a3280ec6734b1437a32",
    "41ff46ee42708e7fee2b2492be4a6c92e32281f33d5dc9bbb639ab7aa55cd7df8bcebe47771f",
    "33b7c876cf01eaa4dcc81e9a78290189dbba85f6d87abbb55b34e2aedfceadf4f00741daceec",
    "23469a714077ddd131ca6a1aa0d7838e610432be3ff18364d96f46d12dbf1cbcd0005982aed9",
    "eaf09d9df96d653b16ee2a01ba02d9106b81c70c8a7a6bb0bd6b3aa07a4a2ad421b670f15a4f",
    "86a5eaa7d9bcbc5709cc96fdd0290f990aa78a189eb3341202c88612940de4e62ced51084270",
    "f60e43785eef5fb1d2349bb6b966a491a6d979cb536699ad808010e2c55fb230d28198e99577",
    "6a7e1ed454a573b983d0e56adfd165cbf86d81a3e119de9943eac93bf18ab4bda9aee81bb06d",
    "6761df11b468aac7ebc1f2dcc4ca111a0bbacd943ea6cd6c31f6ba0129dc6e9f1886e5e7b849",
    "e12147c24012be4d0590616135863c964d806f915b3fadc630a159e47f165039618876a4c4a2",
    "f280c013bffa7666617b8780ee25e9acb08cbf0753c15c473981c4dd8aaccde586d17ab00f2f",
    "c161cea22e50e9e479baaf2cedfd60168beb110d0f9ec67b36af98c3d205cbb6d02c6e56a3d5",
    "9f4e7833df2a23cd33262844f6991ca449a185a7f616d9965e0d42a72c7ef583c601e46c73c5",
    "529b5f871350e5856c3c21daf12b585f7bd990dbb95073274c90e087fd9a22b141dbe6465134",
    "6356af5b51a5d171ae86e6e12cba68bb29f1d444856cfe9c9b8ddd55ae0539f6b99d654f365a",
    "2a379d7f39f10f1945bb7f5063f063862b3aa99cf2deeb053381f75041523300504b54fe0983",
    "4c871afbfdbbdde0ea6d2856d14200000000000000b49d55b4c53f292c50415220434f4d0072",
    "6172706172206f7261636c652067663136"
);

/// Decode one of the hex constants above.
fn from_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex must be byte-aligned");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}

fn set_par3() -> Vec<u8> {
    from_hex(SET_PAR3_HEX)
}

fn set16_par3() -> Vec<u8> {
    from_hex(SET16_PAR3_HEX)
}

/// `a.bin`: 5000 bytes, byte i = (i * 7 + 3) & 0xff.
fn a_bin() -> Vec<u8> {
    (0..5000u32).map(|i| (i * 7 + 3) as u8).collect()
}

/// `b.txt`: the ten letters `qrstuvwxyz`.
fn b_txt() -> Vec<u8> {
    b"qrstuvwxyz".to_vec()
}

/// `sub/c.bin`: 4000 bytes, byte i = (i * 13 + 1) & 0xff.
fn c_bin() -> Vec<u8> {
    (0..4000u32).map(|i| (i * 13 + 1) as u8).collect()
}

/// `big.bin`: 30050 bytes, byte i = ((i * 31) ^ (i >> 7)) & 0xff.
fn big_bin() -> Vec<u8> {
    (0..30050u32).map(|i| ((i * 31) ^ (i >> 7)) as u8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const SET_ID: InputSetId = InputSetId([0x24, 0xa1, 0xad, 0x60, 0x1a, 0xe5, 0xbc, 0x72]);
const SET16_ID: InputSetId = InputSetId([0xb4, 0x9d, 0x55, 0xb4, 0xc5, 0x3f, 0x29, 0x2c]);

fn scan(data: &[u8]) -> Vec<(u64, Packet)> {
    scan_packets(data).expect("the oracle index scans")
}

fn file_named<'a>(set: &'a Par3Set, path: &str) -> &'a par3_rs::Par3File {
    set.files()
        .iter()
        .find(|file| file.path() == path)
        .unwrap_or_else(|| panic!("{path} is in the set"))
}

// ---------------------------------------------------------------------------
// 1 and 2: the hashes, against values the reference reported.
// ---------------------------------------------------------------------------

#[test]
fn regenerated_inputs_hash_to_the_values_the_reference_reported() {
    assert_eq!(
        hex(&fingerprint(&a_bin())),
        "99dac71e48bb629da58fe862e286769a"
    );
    assert_eq!(
        hex(&fingerprint(&b_txt())),
        "bc094a8703d2ce996403c13225b97a81"
    );
    assert_eq!(
        hex(&fingerprint(&c_bin())),
        "de50e34037f9dac160cf99f04c560b9a"
    );
    assert_eq!(
        hex(&fingerprint(&big_bin())),
        "46ef7bc5a5bfd952597ce19fcb4d1d3a"
    );
}

// ---------------------------------------------------------------------------
// 4: every typed packet parses, and writes back byte for byte.
// ---------------------------------------------------------------------------

#[test]
fn the_index_holds_the_packets_the_reference_reported() {
    let data = set_par3();
    let packets = scan(&data);
    assert_eq!(packets.len(), 11);
    assert!(packets.iter().all(|(_, p)| p.input_set_id() == SET_ID));

    let mut counts = std::collections::BTreeMap::new();
    for (_, packet) in &packets {
        *counts.entry(packet.packet_type()).or_insert(0usize) += 1;
    }
    assert_eq!(counts[&PacketType::Creator], 1);
    assert_eq!(counts[&PacketType::Comment], 1);
    assert_eq!(counts[&PacketType::Start], 1);
    assert_eq!(counts[&PacketType::CauchyMatrix], 1);
    assert_eq!(counts[&PacketType::File], 3);
    assert_eq!(counts[&PacketType::Directory], 1);
    assert_eq!(counts[&PacketType::Root], 1);
    assert_eq!(counts[&PacketType::ExternalData], 2);
}

#[test]
fn the_start_packet_matches_the_reference() {
    let data = set_par3();
    let start = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::Start(start) => Some(start),
            _ => None,
        })
        .expect("a Start packet");
    assert_eq!(
        start,
        StartPacket {
            parent_input_set_id: InputSetId::ZERO,
            parent_root_hash: [0u8; 16],
            block_size: 2000,
            galois_field: GaloisField {
                size: 1,
                generator: 0x1d,
            },
            legacy_random: None,
        }
    );
    assert_eq!(start.galois_field.polynomial(), Some(0x11d));
    assert!(!start.has_parent());
}

#[test]
fn the_gf16_start_packet_matches_the_reference() {
    let data = set16_par3();
    let start = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::Start(start) => Some(start),
            _ => None,
        })
        .expect("a Start packet");
    assert_eq!(start.block_size, 100);
    assert_eq!(start.galois_field.size, 2);
    assert_eq!(start.galois_field.generator, 0x100b);
    assert_eq!(start.galois_field.polynomial(), Some(0x1100b));
}

#[test]
fn the_root_packet_matches_the_reference() {
    let data = set_par3();
    let root = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::Root(root) => Some(root),
            _ => None,
        })
        .expect("a Root packet");
    assert_eq!(root.lowest_unused_block_index, 5);
    assert_eq!(root.attributes, 0);
    assert!(!root.is_absolute_path());
    assert!(root.option_hashes.is_empty());
    assert_eq!(root.children.len(), 3);
}

#[test]
fn the_cauchy_matrix_packet_matches_the_reference() {
    let data = set_par3();
    let matrix = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::CauchyMatrix(matrix) => Some(matrix),
            _ => None,
        })
        .expect("a Cauchy Matrix packet");
    // The reference writes zeros, which mean "every input block".
    assert!(matrix.range.covers_all());
    assert_eq!(matrix.recovery_block_hint, 0);
    assert_eq!(
        matrix,
        CauchyMatrixPacket::parse(&[0u8; 24]).expect("parses")
    );
}

#[test]
fn the_file_packets_match_the_reference() {
    let data = set_par3();
    let mut files: Vec<FilePacket> = scan(&data)
        .into_iter()
        .filter_map(|(_, packet)| match packet.into_body() {
            PacketBody::File(file) => Some(file),
            _ => None,
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(files.len(), 3);

    let a = &files[0];
    assert_eq!(a.name, "a.bin");
    assert_eq!(hex(&a.fingerprint), "99dac71e48bb629da58fe862e286769a");
    assert_eq!(a.file_size(), Some(5000));
    assert!(a.option_hashes.is_empty());
    assert_eq!(a.chunks.len(), 1);
    match &a.chunks[0] {
        ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } => {
            assert_eq!(*length, 5000);
            assert_eq!(*first_block_index, Some(0));
            // 5000 = two 2000-byte blocks plus a 1000-byte tail, described by
            // hashes because it is at least 40 bytes long.
            match tail {
                ChunkTail::Described {
                    block_index,
                    offset,
                    ..
                } => {
                    assert_eq!(*block_index, 2);
                    assert_eq!(*offset, 0);
                }
                other => panic!("unexpected tail: {other:?}"),
            }
        }
        other => panic!("unexpected chunk: {other:?}"),
    }

    let b = &files[1];
    assert_eq!(b.name, "b.txt");
    assert_eq!(b.file_size(), Some(10));
    match &b.chunks[0] {
        ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } => {
            assert_eq!(*length, 10);
            // Shorter than one block, so there is no first-block index.
            assert_eq!(*first_block_index, None);
            assert_eq!(tail, &ChunkTail::Inline(b_txt()));
        }
        other => panic!("unexpected chunk: {other:?}"),
    }

    let c = &files[2];
    assert_eq!(c.name, "c.bin");
    assert_eq!(c.file_size(), Some(4000));
    match &c.chunks[0] {
        ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } => {
            assert_eq!(*length, 4000);
            assert_eq!(*first_block_index, Some(3));
            // Exactly two blocks, so no tail at all.
            assert_eq!(tail, &ChunkTail::None);
        }
        other => panic!("unexpected chunk: {other:?}"),
    }
}

#[test]
fn the_directory_packet_names_the_c_bin_file_packet() {
    let data = set_par3();
    let packets = scan(&data);
    let directory: DirectoryPacket = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::Directory(directory) => Some(directory.clone()),
            _ => None,
        })
        .expect("a Directory packet");
    assert_eq!(directory.name, "sub");
    assert_eq!(directory.children.len(), 1);

    let c_bin_hash = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::File(file) if file.name == "c.bin" => Some(packet.hash()),
            _ => None,
        })
        .expect("the c.bin File packet");
    assert_eq!(directory.children[0], c_bin_hash);
}

#[test]
fn the_external_data_packets_cover_the_full_blocks_only() {
    let data = set_par3();
    let mut ranges: Vec<Vec<u64>> = scan(&data)
        .into_iter()
        .filter_map(|(_, packet)| match packet.into_body() {
            PacketBody::ExternalData(ext) => Some(ext.block_indices().collect()),
            _ => None,
        })
        .collect();
    ranges.sort();
    // Block 2 holds a.bin's tail, so the reference leaves it out.
    assert_eq!(ranges, vec![vec![0u64, 1], vec![3u64, 4]]);
}

#[test]
fn the_gf16_external_data_packet_omits_the_tail_block() {
    let data = set16_par3();
    let ext = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::ExternalData(ext) => Some(ext),
            _ => None,
        })
        .expect("an External Data packet");
    assert_eq!(ext.first_block_index, 0);
    // 301 blocks, of which block 300 holds the 50-byte tail.
    assert_eq!(ext.checksums.len(), 300);
}

#[test]
fn the_creator_and_comment_texts_match_the_reference() {
    let data = set_par3();
    let packets = scan(&data);
    let creator = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::Creator(creator) => Some(creator.text().into_owned()),
            _ => None,
        })
        .expect("a Creator packet");
    assert!(creator.starts_with("par3cmdline version 0.0.1"));
    let comment = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::Comment(comment) => Some(comment.text().into_owned()),
            _ => None,
        })
        .expect("a Comment packet");
    assert_eq!(comment, "rarpar oracle");
}

#[test]
fn every_packet_writes_back_byte_for_byte() {
    for data in [set_par3(), set16_par3()] {
        for (offset, packet) in scan(&data) {
            let start = offset as usize;
            let end = start + packet.len() as usize;
            assert_eq!(
                packet.to_bytes(),
                &data[start..end],
                "packet at offset {offset} did not round-trip"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5: the whole file round-trips.
// ---------------------------------------------------------------------------

#[test]
fn the_index_files_round_trip_whole() {
    for data in [set_par3(), set16_par3()] {
        let rebuilt: Vec<u8> = scan(&data)
            .into_iter()
            .flat_map(|(_, packet)| packet.to_bytes())
            .collect();
        assert_eq!(rebuilt, data);
    }
}

// ---------------------------------------------------------------------------
// 6: the sets.
// ---------------------------------------------------------------------------

#[test]
fn the_set_resolves_the_reference_paths_and_sizes() {
    let data = set_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    let sets = Par3Set::from_packets(packets).expect("builds");
    assert_eq!(sets.len(), 1);
    let set = &sets[0];

    assert_eq!(set.input_set_id(), SET_ID);
    assert_eq!(set.block_size(), 2000);
    assert_eq!(set.block_count(), 5);
    assert_eq!(set.galois_field().size, 1);
    assert!(!set.is_absolute_path());
    assert_eq!(set.parent_input_set_id(), None);

    let paths: Vec<&str> = set.files().iter().map(|file| file.path()).collect();
    assert_eq!(paths, ["a.bin", "b.txt", "sub/c.bin"]);
    let sizes: Vec<u64> = set.files().iter().map(|file| file.size()).collect();
    assert_eq!(sizes, [5000, 10, 4000]);

    assert_eq!(set.directories().len(), 1);
    assert_eq!(set.directories()[0].path(), "sub");
    assert_eq!(set.directories()[0].name(), "sub");

    assert_eq!(set.matrix_packets().len(), 1);
    assert!(set.recovery_packets().is_empty());
    assert_eq!(set.comments(), ["rarpar oracle"]);
    assert_eq!(set.duplicate_packet_count(), 0);
    assert_eq!(set.unknown_packet_count(), 0);
    assert_eq!(set.unparsed_packet_count(), 0);

    // Four block checksums, for the four full-size blocks.
    assert_eq!(set.block_checksums().len(), 4);
    assert!(set.block_checksum(2).is_none());
}

#[test]
fn the_gf16_set_reports_its_field_and_block_count() {
    let data = set16_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    let set = Par3Set::from_packets_for(packets, SET16_ID).expect("builds");
    assert_eq!(set.block_size(), 100);
    assert_eq!(set.block_count(), 301);
    assert_eq!(set.galois_field().polynomial(), Some(0x1100b));
    assert_eq!(set.files().len(), 1);
    assert_eq!(set.files()[0].path(), "big.bin");
    assert_eq!(set.files()[0].size(), 30050);
    assert!(set.directories().is_empty());
    assert_eq!(set.comments(), ["rarpar oracle gf16"]);
}

// ---------------------------------------------------------------------------
// 7: verification against the regenerated inputs.
// ---------------------------------------------------------------------------

fn oracle_set() -> Par3Set {
    let data = set_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    Par3Set::from_packets_for(packets, SET_ID).expect("builds")
}

#[test]
fn the_regenerated_inputs_verify_complete() {
    let set = oracle_set();
    for (path, data) in [
        ("a.bin", a_bin()),
        ("b.txt", b_txt()),
        ("sub/c.bin", c_bin()),
    ] {
        assert_eq!(
            verify_file(&set, file_named(&set, path), &data),
            FileVerdict::Complete,
            "{path} should verify"
        );
    }
}

#[test]
fn the_gf16_input_verifies_complete() {
    let data = set16_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    let set = Par3Set::from_packets_for(packets, SET16_ID).expect("builds");
    assert_eq!(
        verify_file(&set, &set.files()[0], &big_bin()),
        FileVerdict::Complete
    );
}

#[test]
fn a_flipped_byte_in_a_bin_localises_to_block_one() {
    let set = oracle_set();
    let mut data = a_bin();
    data[2500] ^= 0x01;
    let verdict = verify_file(&set, file_named(&set, "a.bin"), &data);
    assert_eq!(verdict.damaged_blocks(), [1]);
    match verdict {
        FileVerdict::Damaged {
            expected_size,
            actual_size,
            unchecked_blocks,
            damaged_chunks,
            ..
        } => {
            assert_eq!(expected_size, 5000);
            assert_eq!(actual_size, 5000);
            assert!(unchecked_blocks.is_empty());
            assert!(damaged_chunks.is_empty());
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn a_flipped_byte_in_a_bins_tail_names_the_chunk_not_a_block() {
    let set = oracle_set();
    let mut data = a_bin();
    // Block 2 holds a.bin's 1000-byte tail; the set carries no checksum for it,
    // so the tail's own hashes in the File packet are what catch this.
    data[4500] ^= 0x01;
    match verify_file(&set, file_named(&set, "a.bin"), &data) {
        FileVerdict::Damaged {
            damaged_blocks,
            damaged_chunks,
            ..
        } => {
            assert!(damaged_blocks.is_empty());
            assert_eq!(damaged_chunks, vec![0usize]);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn a_flipped_byte_in_b_txts_inline_tail_is_caught() {
    let set = oracle_set();
    let mut data = b_txt();
    data[4] ^= 0x20;
    match verify_file(&set, file_named(&set, "b.txt"), &data) {
        FileVerdict::Damaged {
            damaged_blocks,
            damaged_chunks,
            ..
        } => {
            // b.txt occupies no input block at all: its ten bytes live inside the
            // File packet, so only the chunk can be named.
            assert!(damaged_blocks.is_empty());
            assert_eq!(damaged_chunks, vec![0usize]);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

/// A truncated file is reported as `Damaged` with both sizes, not as a distinct
/// size-mismatch verdict: the truncation is visible in the fields, and the same
/// verdict still carries the block-level detail.
#[test]
fn a_truncated_c_bin_reports_both_sizes_and_the_lost_block() {
    let set = oracle_set();
    let data = c_bin();
    match verify_file(&set, file_named(&set, "sub/c.bin"), &data[..2500]) {
        FileVerdict::Damaged {
            expected_size,
            actual_size,
            damaged_blocks,
            ..
        } => {
            assert_eq!(expected_size, 4000);
            assert_eq!(actual_size, 2500);
            // Block 3 is still whole; block 4 is gone.
            assert_eq!(damaged_blocks, vec![4u64]);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn a_missing_file_is_reported_as_missing() {
    let set = oracle_set();
    let dir = std::env::temp_dir().join(format!("par3-rs-oracle-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).expect("temp dir");
    std::fs::write(dir.join("a.bin"), a_bin()).expect("write");
    std::fs::write(dir.join("b.txt"), b_txt()).expect("write");

    let report = par3_rs::verify_set(&set, &dir).expect("verifies");
    assert_eq!(report.missing_count(), 1);
    assert_eq!(report.complete_count(), 2);
    let missing = report
        .files()
        .iter()
        .find(|file| file.verdict().is_missing())
        .expect("one missing file");
    assert_eq!(missing.path(), "sub/c.bin");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_block_checksums_match_the_regenerated_inputs() {
    let set = oracle_set();
    let a = a_bin();
    let c = c_bin();
    let expected: Vec<(u64, &[u8])> = vec![
        (0, &a[0..2000]),
        (1, &a[2000..4000]),
        (3, &c[0..2000]),
        (4, &c[2000..4000]),
    ];
    for (index, block) in expected {
        let checksum: &BlockChecksum = set
            .block_checksum(index)
            .unwrap_or_else(|| panic!("block {index} has a checksum"));
        assert_eq!(checksum.rolling_hash, par3_rs::rolling_hash(block));
        assert_eq!(checksum.fingerprint, fingerprint(block));
    }
}

// ---------------------------------------------------------------------------
// 8: robustness, on real bytes rather than synthetic ones.
// ---------------------------------------------------------------------------

#[test]
fn junk_between_packets_is_skipped() {
    let data = set_par3();
    let packets = scan(&data);
    let mut noisy = Vec::new();
    for (offset, packet) in &packets {
        let start = *offset as usize;
        noisy.extend_from_slice(&data[start..start + packet.len() as usize]);
        // Enough junk to include a false magic sequence.
        noisy.extend_from_slice(b"PAR3\x00PKTnot a packet at all");
    }
    let recovered = scan(&noisy);
    assert_eq!(recovered.len(), packets.len());
    for ((_, expected), (_, actual)) in packets.iter().zip(recovered.iter()) {
        assert_eq!(expected.hash(), actual.hash());
    }
}

#[test]
fn a_flipped_byte_makes_the_scanner_drop_exactly_one_packet() {
    let data = set_par3();
    let packets = scan(&data);
    let (offset, packet) = &packets[3];
    let mut damaged = data.clone();
    damaged[*offset as usize + 60] ^= 0x01;
    let recovered = scan(&damaged);
    assert_eq!(recovered.len(), packets.len() - 1);
    assert!(recovered.iter().all(|(_, p)| p.hash() != packet.hash()));
}

#[test]
fn every_truncation_of_the_index_scans_without_panicking() {
    let data = set_par3();
    for len in 0..data.len() {
        let _ = scan_packets(&data[..len]);
    }
}

#[test]
fn every_single_byte_flip_scans_without_panicking() {
    let data = set_par3();
    for index in (0..data.len()).step_by(7) {
        let mut damaged = data.clone();
        damaged[index] ^= 0xff;
        let _ = scan_packets(&damaged);
    }
}

#[test]
fn a_duplicated_index_yields_one_set_and_a_duplicate_count() {
    let mut data = set_par3();
    let original = data.clone();
    data.extend_from_slice(&original);
    let packets = scan(&data);
    assert_eq!(packets.len(), 22);

    let set = Par3Set::from_packets_for(packets.into_iter().map(|(_, p)| p).collect(), SET_ID)
        .expect("builds");
    assert_eq!(set.duplicate_packet_count(), 11);
    assert_eq!(set.files().len(), 3);
}

#[test]
fn a_file_packet_before_its_start_packet_is_still_typed() {
    // The scanner sees packets in file order, so put a File packet first and the
    // Start packet last; the deferred parse must still resolve it.
    let data = set_par3();
    let packets = scan(&data);
    let mut reordered: Vec<u8> = Vec::new();
    let mut start_bytes = Vec::new();
    for (_, packet) in &packets {
        if packet.packet_type() == PacketType::Start {
            start_bytes = packet.to_bytes();
        } else {
            reordered.extend_from_slice(&packet.to_bytes());
        }
    }
    reordered.extend_from_slice(&start_bytes);

    let rescanned = scan(&reordered);
    assert_eq!(rescanned.len(), 11);
    let typed = rescanned
        .iter()
        .filter(|(_, packet)| matches!(packet.body(), PacketBody::File(_)))
        .count();
    assert_eq!(typed, 3);
}

#[test]
fn a_file_packet_alone_stays_opaque_and_round_trips() {
    let data = set_par3();
    let (offset, packet) = scan(&data)
        .into_iter()
        .find(|(_, packet)| packet.packet_type() == PacketType::File)
        .expect("a File packet");
    let start = offset as usize;
    let bytes = &data[start..start + packet.len() as usize];

    let alone = Packet::parse(bytes, 0, &ParseContext::new()).expect("parses");
    assert!(matches!(
        alone.body(),
        PacketBody::Opaque {
            packet_type: PacketType::File,
            ..
        }
    ));
    assert_eq!(alone.to_bytes(), bytes);
}
