# Attack explanation

## Sources of knowledge

- @liveoverflow
- https://www.loyalty.org/~schoen/rsa/

## Atack history

 In February 2012, two groups of researchers revealed that large numbers of RSA encryption keys 
 that are actively used on the Internet can be cracked because the random numbers used to 
 generate these keys were not random enough. 

## How does the RSA work?

To understand how does the attack work we first need to understand how does RSA work and how 
does the Euclidian algorithm work.
RSA is based on the fact that there is only one way to break a given integer down into a 
product of prime numbers, and a so-called trapdoor problem associated with this fact. 
It's easy to fall through a trap door, but pretty hard to climb up through it again.
The particular problem here is that multiplication is pretty easy to do:

```
    p * q = n; ex. 100 * 2 = 200
```

, but reversing the multiplication in the form of factoring is very hard:

```
    200 = p * q;
```

It seems as though this pattern continues, and factoring gets drastically harder as the numbers 
involved get larger, while multiplication remains easy and quick. In fact, there is also a 
longstanding public challenge to see what the public state-of-the art in factorization is. 
The largest number from this challenge that we know has been successfully factored is called 
RSA-768 (data from 2012, found in 2009):
1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413
The RSA algorithm requires a user to generate a key-pair, made up from a publick key and a 
private key using this assymetry of multiplication and factorization. Descriptions of 
RSA often say that the private key is a pair of large prime numbers (p, q), while the public 
key is their product n = p × q.

This is not exactly correct, in reality there are also 2 numbers called d and e involved;
e, which is used for encryption, is usually 65537, while d, which is used for decryption, 
is calculated from e, p, and q. The way we calculate d is straightforward to do but 
complicated to explain, and isn't really necessary for the purpose of the attack. The end
result is that d can be used to decrypt what e and n encrypt using the modular 
exponentiation, but only the private key owner knows and can calculate d. 
n on the other hand is published as part of the public key. Not only is the public allowed to 
know this number, but for security reasons the public key holder normally wants everyone to 
know it, to prevent someone else from maliciously impersonating them by giving out some other 
value of n. box to someone living on a park bench". My computer could be the equivalent of the park bench.)

It's reasonable to say that the security of RSA is based on keeping p and q secret, and on its 
being just too hard to figure them out from n by factorizing it. If you can find the factors 
of any of the last three numbers above, you can break the security of that key and of some of 
the private data that it protects.

## Cracking keys with gcd

Although factorization is a hard problem, there is another problem that is much easier - finding 
the greatest common divisor of 2 numbers or the largest integer that both numbers are 
divisible by. Examples:

```
    gcd(6, 9) = 3
    gcd(10, 12) = 2
    gcd(10, 30) = 10
    gcd(100, 144) = 4
    gcd(3, 7) = 1
```

One interesting observation is that gcd(p, q) is always 1 if p and q are prime. 
However, gcd(x, y) can also be 1 if x and y are not prime but just don't have any divisors in 
common. For example, gcd(16, 27) = 1 because there is no other number that 16 and 27 are both 
divisible by. So 16 and 27 are called relatively prime to each other. There is a very ancient 
and very fast method for calculating gcd, even for extremely large numbers, which will be 
explained later in the text. 
Suppose there are four different primes, a, b, c, and d. The first two are used in one key, 
in the public value n1 = a × b. The other two are used in another key, in the public value 
n2 = c × d. What is gcd(n1, n2)?

n1 and n2 must be relatively prime to each other. (There can't be any number other than 1 that 
both of them are divisible by, because if there were such a number, it would have to be one of 
the four primes a, b, c, or d. But n1 isn't divisible by c or d, and n2 isn't divisible by 
a or b. https://en.wikipedia.org/wiki/Fundamental_theorem_of_arithmetic
From this simple, but beautiful ancient conclusion we have many later important science 
discoveries and apparently we can break crypto ciphers.
So, gcd(n1, n2) = 1 and this hasn't given us any new information about the values of a, b, c, 
and d. And that's a good thing for the security of these RSA keys, because it provides no 
shortcut to factorizing them! But what if we re-used somehow between 2 different RSA keys?
In this scenario, there are now only three different primes a, b, and c. Somehow, 
b has been re-used in two different keys, so the public values are n1 = a × b and 
n2 = b × c. In this case, the re-use of a prime number across keys turns out to be extremely 
significant, and extremely bad for the security of those keys.

The security problem comes in if someone comes across both public keys and, looking at the 
public values n1 and n2, decides out of curiosity to calculate gcd(n1, n2). This time, the 
result is not 1, but rather b, because both n1 and n2 are evenly divisible by b!

Noticing this leads quickly to cracking both keys, because now it's easy to calculate 
a = n1 / b and c = n2 / b. That reveals both of the secret prime factors of both keys, 
which is enough to derive a complete private key for each and start decrypting encrypted 
messages. 


### How unlikely is it that a prime number would be reused in 2 defferent keys?

We normally choose these primes at "random", so for modern key sizes it's extremely 
unprobable, but the attack relies on the random number generator failing to produce truly
random numbers. That is why we seperate random number generators on truly random and 
pseudo-random number generators. meaning that some algorithms, well a lot of them actually
generate random numbers not primarily by measuring a physical quantity like radio static or 
lava lamp patterns but rather by using some sort of formula that gets fed with some (ideally) 
unpredictable value called a "seed". We truly unpredictable seeds from a large enough pool of 
possibilities.

### Euclids algorithm

Donald Knuth: "The Euclidian algorithm is the oldest nontrivial algorithm that has survived to 
the present day".

Euclid's core observation is that if: 
```
a ≥ b and b > 1, gcd(a, b) = gcd(a-b, b).
```
Or in a simple way of stating the subtraction-based form of Euclid's algorithm is: to find the 
greatest common divisor of two numbers, replace the larger number with the smaller number 
subtracted from the larger. Repeat this until one of the numbers reaches 1 
(in which case the gcd is 1, and the numbers are relatively prime) or until one of the numbers 
reaches 0 (in which case the gcd is the remaining value of the other number).

To note, although  Euclid's gcd is incredibly fast compared to trying to factor numbers, 
it would still take quite a long time to apply to to every pair of RSA public keys on the whole 
Internet—since there are millions of them and the number of possible pairs of things grows 
with the square of the number of things. There are still further tricks to make this process 
even faster in this case.

