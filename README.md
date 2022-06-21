Whiskey Tango
=============

This is a simplified web token format that has the property that you can't get aaccess to the claims unless you followed the correct signature check protocol.  Most of the problems with JWT have to do with the fact that its design allows a large number of hazardous practices.

- It has a complex RFC that goes beyond the simple and easy to understand uses of jwt.io, making it difficult to implement correctly.

- When correctly implemented, it is full of hazards that should be disabled completely.  So this implies that implementing the full standard is a security hazard.

- One hazard is that the algorithm is specified by the token.  A trivial to forge token such as an `alg:None` token is considered valid.  Things like this make JWTs hazardous to handle.

- The other hazard is that it is possible to retrieve claims without bothering to check the signature.  The format encourages this.  Because JWTs are checked from many languages, it's highly probable that some clients will just extract the claims and hope that somebody else did the signature check; if they even care.

- Another hazard is that the JWT itself tells a client where to download the trust for the file.  The token should not be telling you where to do this, because real libraries deal with this by automatically downloading the trust of unknown files.  This completely defeats the point of doing a signature check in the first place.  A better idea is that if you have a trust store, such as a JWK, you may want to have the trust file add information to help rotate to new signing keys.  This means that the trust file, that you actually trust; tells you how to do this, instead of a JWT that you don't trust.  This basically means that the `alg` field should go away from JWT, and the details of how signing happens should be in the trust file that includes a JWK.

Encrypted JWTs involve a complex specification in JOSE, that just compounds the complexity problem associated with JWT hazards.  There are many situations where the CA has the signing key, and only clients allowed to decrypt the claims need to check the validity of those claims.  So, the public keys to verify a JWT can actually be secrets in that situation.

# Tokens

Tokens are digitally signed claims about a user.  This is an example of what is being digitally signed:

```json
{
  "exp": 1655843670,
  "groups": {
    "age": [
      "adult"
    ],
    "awards": [
      "cherryblossom-go-tournament",
      "best-dad"
    ],
    "email": [
      "rob.fielding@gmail.com",
      "rrr00bb@yahoo.com"
    ]
  },
  "kid": "usa:1234:1"
}
```

It needs to be digitally signed, because we will make critical security decisions based on it.  We can do that if we are given the trust file for the signer, which looks like this:

```json
{
  "kty": "RSA",
  "kid": "usa:1234:1",
  "n": "qeIhwbmDXoH_ngks_fexyDCBFI_kh8Q54vDefHi-dvIfqlOEOPiMqUd471muLhl5HNZy2laCULaNEaVvWm-eMpRTFwYgvP1ObCdTe5v9mvRUbPheob8j9vymj8skxmhcEEiMLsKx1OzrzClo5Knf7q7KI9SWZ-VOL9bedSh2-t2HPbWzHNNDPx0HZqTFCQhsWKvpqSlagom4qiE-_IUXoEuVe0wbiRH-pbgGal1Yfft5I45y1d_84SilG4ZuXTAxkdU3DjvHxZbJ0n6nMOQG07fJqTC62waSXNkvE6UdiZ-ItmSVsHBLTQevPvce2VVbugZJuROuXQdxiYomLcuYaQ",
  "e": "AQAB"
}
```

This way, if a token has that `kid` in its first part, we can use that semi-public key to decrypt the claims.  The way that the claims are encrypted, we have verified the signature of the signer; and that is the only way to get the claims.  Without the trust file, we have no idea what is in the token.

```
dXNhOjEyMzQ6MQ.EmIl5_1-rp260VkehZn74jXpuShgRArXgZr3YuRytf8c-iXxLRqdywIgshzrA1xI0FkdmR4x-nKdnBrrC_7POPCAcnH3kLsNb8vOo9fFw9OpoLoVbPP7SnDktMtTfNRq8jty8fDz8PqPpv0Vob2R1_-99spdpssPRMjuSXV2wAmSbCg4JVu12pdxLcP4Z9S-o_A9NFzV7475YuFearGZt8-bBcza2q8LqWfz6_xoWDZHk9v5zxx1gqq3yjHZ7Ov2zjmd3MtQaw.bY2VzbnlWqztLpAl4BMGsZ-6VobEoIeJ4K6T1djZJ5gpS4tICKfMvZolaMlTK_lhNH35q-hhq27tHgnjU-0lRAV1qiVQVodwH40i6tjQ6IxakZ7Fv12xu3O5uP8ksz1kCNqAKk3GktiLwG5pZT9eStNu2ncQ_EQfEJXrgAeO66aC1pON9nNh3wN59mlB2vFWPqk70G9X0KHWNxsNzKN0UZahNROk2qIMIErTAj5pNGkvwm9196LAcfgKEwZMNgREwrLe_4mZ37wXpN4XUVsvqwEgAzDo5EsyEC1iIZpp63b_mmsN4mVyCpyy4RmhsaD09ubpV_Q-ve1VLeLc-aRRew
```

It is similar to a JWT in that there is a header, a body, and a signature.  But the header only has the `kid` value in it, the key id to look up the signing key.  The body is encrypted.  It requires an actual signature check to get enough information to extract the claims.  This way, a bad imlementation of this spec can only manage to ignore the expiration date.  The token is at least signed by a trusted signer.  We know this because the `kid` must have an entry for the key.  We don't have a mechanism to fetch unknown keys coming in from the tokens themselves.


The good part of JWT is the idea of a simple json object that is digitally signed.  The existing JWT specification goes roughly like this:

```
var header // a json chunk that includes alg, maybe kid, etc.
var claims // A json chunk that includes exp, issuer, etc.
var signature // a signatuer over header and claims, ensure no modifications.
jwt = join(".", [B64UEncode(header), B64UEncode(claims), B64UEncode(signature)]
```

This uses the common method of signature checking.  For RSA, the check would be this pattern:

```
signature = RSASign(priv, Sha256(plaintext))
signedPlaintext = (plaintext,signature)
```

This is a very common pattern in cryptograpy, to give the plaintext and a signed hash of the plaintext.  The problem with this pattern is that it is _consentual_ for the verifier to bother verifying the signature.  This is because it is easy for the verifier to skip the signature check entirely, and simply return the plaintext.  That is ok if the CA is not put at risk by clients that follow protocol.  But it's very easy to just extract that claims and not check the signature, and JWT tokens are used from many languages.  Many developers just don't care about the signatures, or the details of any libraries they are using.

We want a foolproof way of checking, such that if the client can even manage to get the plaintext, we are assured that the protocol was followed.  The only problem we have that we can't solve is verifying that the client actually checked an expiration date on a token.  But we can force the data to stay encrypted without a signature check, by forcing a signature check to produce a witness to decrypt the data.


A CA is setup with a key:

```
# Assign some kind of name for keypair, the "key id"
kid = ArbitraryNameForKeypair()

# The RSA key pair that is used for (sign, verify):
(s,v) = RSAKeypair()

# the verify is "public" to those that are _allowed_ to decrypt the tokens.
# that means that v is not entirely public.  s is secret to the CA only.
```

A client will _trust_ a `kid` by mapping from `kid` to `v` in a JWK

```
# the trusts map is generally a JWK file, where this is true
trusts[kid].v == v
```
	
When the CA is asked to sign claims, for clients that trust a `kid`,	
this is how a token is created by the CA, 
given `claims` for a `kid`, and a validity period:

```
# The witness key `k` that lets us decrypt the claims:
k = randomAESKey()

# Mandatory modifications to claims to ensure expiration,
# and allow lookup of issuer information
claims.exp = expirationDate(validityPeriod)
claims.kid = kid

## The algorithm to create a signature Sig for the claims
# encrypt the claims to the witness k
E = AESEncrypt(k, claims)
# a hash of the ciphertext
HE = Sha256(E)
# sign both k and ciphertext, so that we can recover k from HE and v
V = Xor(K, HE)
Sig = RSASign(s, V)
Token = join(".", map(B64E, [kid, E, Sig]))
```

That token will bear a superficial resemblance to a JWT token.  The differences,

- The header _only_ has the kid value in it.  Substituting a wrong value will cause the claims to fail to decrypt.  Importantly, it does not specify the algorithm, as once we look up a kid, all of that information should be in our trust store; as information that we already trust to be correct.

- The claims are encrypted.  If you were not given the trust entry for this kid, then you cannot decrypt it either.  So this token can contain secrets, so long as the trust is only given to clients entrusted to decode the claims; so the tokens don't leak information to intermediate services that see the token in headers.

When a client gets a token, it is required that the client posesses a JWK entry for kid.  Crucially, we don't give the client a method to look it up; which defeats the purpose of having a signature in the first place.  The client has: `token`, `trusts[kid]`.

```
kid = token.kid
E = token.E
#client does NOT have trusts[kid].s !!
v = trusts[kid].v 
HE = Sha256(E)
Sig = token.Sig
V = VerifyRSA(v,Sig)
k = Xor(V,HE)
claims = AESDecrypt(k, E)
```

Most signature checks simply trust that the client is defending itself and checking the signature.  But the sort of people handling JWTs will simply extract the claims without checking if that's possible; because it makes the code simpler.  So, we require that the signature check generate a witness in order to get the plaintext claims.

- k is the witness
- require that HE be produced by the client
- require that V be produce by the client, using VerifyRSA(v,Sig)
- Xor(V,HE) = Xor(Xor(k,HE),HE) = k
- k it a witness that the signature was checked, so we can decrypt claims. `claims = AESDecrypt(k, E)

It is unusual to do a setup that requires a witness that verification actually happened.  But if you are going to have encrypted tokens, the tokens need verification, and the claims need a decrypt.  This just means that the RSA public key that kid leads to is not _entirely_ public.  It's public to those allowed to verify the token.


```


2022/06/21 15:42:20 public key 1: { "kty": "RSA", "kid": "usa:1234:1", "n": "8UhP2K9r9OWadtSy8PyL-YqS2CkLXesTPuSmLkxHMge6tDDPvecqIZfwiO_7plWZ9NH5aufhpvqCOy6qF-f3N3gHWA-U4O_HNFpj31PuUaduP7otsl2YUIH-MepbnfjDgyI4GJ-jcNK1vbg4GYLBJt0elHlGK9wkZHsmgrUhAgMLI_BWeIoHT7-gIBTtCh-k-xzWoGkgI8BtVkAwlodyVMQ_44ZnnoiLgrfa8LY0ORN5HHNxUBkvYzcrfXH9zElQ2TPsta9b5tVbSwGHsf2NNIDrty4lNNQzyjPDDNd_0dvF5TEyGZgwk7nmi-bJ4lLvj8MU3C53zTEbkz1tYgaB5Q", "e": "AQAB" } 



2022/06/21 15:42:20 private keys: { "keys": [ { "kty": "RSA", "kid": "usa:1234:1", "d": "W_PC-kFgUyRtiXvl9hFJBwDYlaiOvGwqGX3qFxraxyZK8QDpKuY-GC9fa9CJhwp4ceTTuPpF9OzjVMqj6BhvDqSfp9_ITTEUKc-I4EOMP3IfggniAGfK9GOWDE_UOo_jcsZHupqcHxMuT-808gPyuGzsiojtRSnQdLq6InYE7k6dMUF-2KZ5duU6yxPPRg6yvwAydRMfJm4I7-IvgJp5qPBr_5i8SxBBa9J5u0h_RqwgK75jA1PVOAssAyvdWRh_zvtDSn3OJi9f662EWcBc5O5c6q318Xl2_Y4xgZ-dSP0t_wHxvsNjhO2vBPJotVIhdZpo7TtIgOPYRaMRFKimwQ", "n": "8UhP2K9r9OWadtSy8PyL-YqS2CkLXesTPuSmLkxHMge6tDDPvecqIZfwiO_7plWZ9NH5aufhpvqCOy6qF-f3N3gHWA-U4O_HNFpj31PuUaduP7otsl2YUIH-MepbnfjDgyI4GJ-jcNK1vbg4GYLBJt0elHlGK9wkZHsmgrUhAgMLI_BWeIoHT7-gIBTtCh-k-xzWoGkgI8BtVkAwlodyVMQ_44ZnnoiLgrfa8LY0ORN5HHNxUBkvYzcrfXH9zElQ2TPsta9b5tVbSwGHsf2NNIDrty4lNNQzyjPDDNd_0dvF5TEyGZgwk7nmi-bJ4lLvj8MU3C53zTEbkz1tYgaB5Q", "e": "AQAB", "rsaPublic": { "N": 30459089823765646089725637944757365511368623862461052645433449444862763787239383353325492879673333602703058006322358438302083810858200712344870496398392992558703043691712098100560059597645544329429630534490599704128371468451397882072484113492792623682512854922813891529683829738644289421737415784298104280950458329897560848886584647135932829197266890828926549969419301482081701950787265503606570511426690911808605588789601995635218083891751468590765405193666903062918028045663539678827278795875383880487300829020701795099678018549263267350639874509665287852246633698381329759811256056080658177158502936877670769000933, "E": 65537 }, "rsaPrivate": { "N": 30459089823765646089725637944757365511368623862461052645433449444862763787239383353325492879673333602703058006322358438302083810858200712344870496398392992558703043691712098100560059597645544329429630534490599704128371468451397882072484113492792623682512854922813891529683829738644289421737415784298104280950458329897560848886584647135932829197266890828926549969419301482081701950787265503606570511426690911808605588789601995635218083891751468590765405193666903062918028045663539678827278795875383880487300829020701795099678018549263267350639874509665287852246633698381329759811256056080658177158502936877670769000933, "E": 65537, "D": 11607889092243629960739544582575643697635576080516765351974393599568066715749741956950386959469020249036598818467540844943052707020376596297137273876531781774359021915012914264607596449498681892241549845574823660074617480141631650863517756665639082794367167623666016980413862879783630202745223257528258121687137484659669397008258987310329606922292849238883995750310167853702463898193170734793453800985008322018368291816282820806804102674707361577308148819980211681793691216816147273516006358454147384860677283764629452511724895012777847706238742966047120693905878297469165696683525460987135307256256344508912737232577, "Primes": [ 174954038902346583448810658868025382416315696426872998351562131159193369813643656454048646434130439653277134854912897052251202901162767310016801289264466977336055860132608537038997511461152515757326179888423969595635139379426526874748815005246282351682084416565731190540182087099532345378147147457386929841339, 174097665963384120469706938424851505981802688203535495728314678112676081939115503215999533348002080094237697177653255084587617818251403246954395495728383675679940584134396714161018763834096148457785061284643279169124780016552715607066247774525101395963750675904455381268663329298475021736582885429227863022047 ], "Precomputed": { "Dp": 111544311785642456060318668387957529012364543074911292294759785897366918905248737984283208608933980659360846587083334458874593924381419187355875689620008364450764576648014329487731693835433369217451471694735907130079476689960754977104604821386555102959919057353594337023833381561054969243030660685711208576689, "Dq": 26931384371222183092327829191924326222492876588910735244116364903891086236763247808166429178663122938117121229031672185903371674648408168174064445056904553214874614980156459529188217766300971253872239365605895360126142786636730866906291406963020552547118488065052850379201196765612398650616862115774479688077, "Qinv": 20133234231747142556058680943724238642361413384024693615698987312700685222341747357630347682413675249023205416423194861040822381004967530543518057101648464441850802052519099596144774403903987202455903736439521124873443065913898032287446157288108718687879972554591621331250095821571665291430195716627945128992, "CRTValues": [] } } }, { "kty": "RSA", "kid": "usa:1234:2", "d": "yh50OiAFrhVvJXkxNI6lFQl9PQ9RS3LB6BTjE4pux65IBftb_HyYkj0FRkkMzxUHLdCFxzEzVVhgIChywuCCZVQAXb71I2pm0HiAmKgNyxu1doc6MZ5XbHO72byM7OL7yhnqDuZOu2DonBbNfF85OfQHsiLBRX51NK65-MWJk33qNcgZFOXlSSfNbJRcKuHn3dZ6DVqu4kFymiQ-DUJzApFBLBOULkql0aJfOEA99tMFnsC5cl1xNoLPMMsLjwQKh2GD_ZqNUsaguZysB_FOwC8q02Cy3gBTCaFCKIToZ-Ore8QAbNJN3PtFakxTZpJ8X5IH-9HJfmnppEe48dvUgQ", "n": "zvaZCwti_eWEpj_jQZ_TupLTgyTiOXYl24p3VQWlH-0_aPsJPjIGoITS5jsCdd2mkUvGWoL86xeBOV0VVAuOegciatkpTrwGK9PELvXcvgdzLv0SLrpa_aw4nHlpt3_Asf-b0OI4TNOzuDWB_p5wYBzOJJurmt4e0bGjZv9JEZeacIXjPoeEifLlfrSes3rhR2llpZ1rCzv7lW9hP99uuEA3W2Je9-kjgwbxi5uRKoXa9Bl4aLWDQlMTfnmViIQA3Jk4ORHl86Cvi16eqofeB36530G0wN3c9Wyym-HkFAmDn62pbb4JFYlLkAv4ABaMGj96SUAUJczzCrw2Y_LmiQ", "e": "AQAB", "rsaPublic": { "N": 26126692742570423818089641206511720695716522666705417006508520694296307521249355673434840477022684630193898921294226887297914188006800764617037202265961236476467601711704223566387139822963806351966618485220884752351391995759832978695599578824361156981231493646794294553180466677078352232687842212508434949380362913540933894018961895136742489903127256501720556135685308965170978028819508689004571649216974931435660391787849257946035714787007075911057184639295635480984980902945948542195761202769647524713569938588462519733231332547778590558377369615688262333440809932310381108355296166757755897529471805728029792200329, "E": 65537 }, "rsaPrivate": { "N": 26126692742570423818089641206511720695716522666705417006508520694296307521249355673434840477022684630193898921294226887297914188006800764617037202265961236476467601711704223566387139822963806351966618485220884752351391995759832978695599578824361156981231493646794294553180466677078352232687842212508434949380362913540933894018961895136742489903127256501720556135685308965170978028819508689004571649216974931435660391787849257946035714787007075911057184639295635480984980902945948542195761202769647524713569938588462519733231332547778590558377369615688262333440809932310381108355296166757755897529471805728029792200329, "E": 65537, "D": 25515155036128215139984913959143226874711149430659731215459432839419664773830393688555321345970717066486108803570416764083317847551753503178116667785042296995641483625344544622419032151138326410194538701948399939038194331516801045752085994834911380293113192362722969227874474094527454383763674948917060012896082685238843639984556890538880401616735404088969293524868238079562261803051061395922908492706267540233169546665123901329792519574933716077987320548530142531918866983951054377983452179452801230198682292444954446199728909021926251626992514116108792690229609530074651937962566013408359625748484658947362647692417, "Primes": [ 146080465503328705152853664291717277827328517182530819718370455174144224274992383186251547167992733409036871088515097584697025650006233035730443077262643437885027937762212919126070582264343276688168602841494218755066432665202707889687949827655333044134091298823447363473889227643612419460454575124450924874577, 178851379289827634826729155112446597520164883139956635759921354234260928483122141410407130993083946628076068551900053812417351771839351217075487295998275684267292222293554682021591226964404067978668504473981416916611011618432315134695569536834986278204459055459302789172257542667982129496630950375569151502777 ], "Precomputed": { "Dp": 79572249843650631631776293720341411739289267664054926730337166474842831719379176455528846031252156643868459969008353581581383320560485117453363556696203794635970708915166074124259482677797131917709552662442621959154623795948417976928607060095331405809587336568629132072788982371016673975292855598635481744625, "Dq": 100244864968693081924565391378084148903798108738270398421795186003129631902139640514953158410805386445658455927444720946816707854112560664309227990965479968722865636228529596025132528801798291485121842239387817379463086344810934767273026775661985610529691540415132968470704126139783443898862393764526628349657, "Qinv": 23021655124539988331595390203994562446908114432307796811158472093595231843296156130533587416768814474849404759493131756071311185467784659564142706898091744755768874062574859382904911834469957768016256439471353188192518978685576274421886457837835057641505732513188898156621931241469380954731027249679180651192, "CRTValues": [] } } } ] } 


2022/06/21 15:42:20 create token: dXNhOjEyMzQ6MQ.tDr4Pprij4R1IW7-RYNpU8y-iOFXu6yJKVocyRY82zbUgeg_Os749DBlz9LwcCHcJnRqLhowWgSGJweameAwSrSUqSRISOg6HbjlHsXC_9KhoDW3SnAkTguW2C3HY53zmruLXhrbC5hTERsCnu_hUmL9ATqx13P-1E9xrBl5jb2h-D-6AAw_IVLZJYIaRTehScAYSUkhDwlyVCd0wOlecj65-wiUobuWDOaqg9vuhh2viLJD7unB5qrWWDSeAqOm8Z1b4Ljmwg.Ey9r6K8QujYbZ6gr-1AC3Q_lBJZiOC9ZEe2s-b_rwnqODqx5SZ2tk43JO_HCb8VXVM92LVguXbyJ2n4VNr74PRL0ZelhIFAUW7xe6lWuveirL8-NsulHgR97A0d5BT-iuqoum2gfb24SnAVMcG2jVXTM-Y-U5qWsDcbTSWzKTNYQQRdPAlqXEP-rud8mwZuAb7EDN89rb6YaWi3SeMypsLhoAEl9dLdbWoB6RT8qVubYuh3j-vomj5J7LuTE1HATI7H_uvIhuvfLf53NfhPCKn6dD_gjq1PhEE3pgSaw0s2YVSKMg41BZesLJ_ZUYmAEyXbaQKd28m9hmVH7l5n14Q 

2022/06/21 15:42:20 validate claims: { "exp": 1655841740, "groups": { "age": [ "adult" ], "awards": [ "cherryblossom-go-tournament", "best-dad" ], "email": [ "rob.fielding@gmail.com", "rrr00bb@yahoo.com" ] }, "kid": "usa:1234:1" }
```
