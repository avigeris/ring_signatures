import argparse
import lsag

parser = argparse.ArgumentParser()
sp = parser.add_subparsers(dest="command")
splist = []   # list to collect subparsers

g = sp.add_parser('generate_keys', help = 'generate new keys for ring signature')
splist.append(g)
g.add_argument('-n', type=int, action='store', help='number of participants in the ring', required=True)
g.add_argument('-i', type=int, action='store', help='number of signer in the ring', required=True)
g.add_argument('-k', type=str, action='store', help='path to save [default: ./data]', nargs='?',  const='./data')

s = sp.add_parser('generate_signature', help = 'generate signature for for message')
splist.append(s)
s.add_argument('-i', type=int, action='store', help='number of signer in the ring', required=True)
s.add_argument('-k', type=str, action='store', help='path to keys [default: ./data]', nargs='?',  const='./data')
s.add_argument('-m', type=str, action='store', help='message')
s.add_argument('-s', type=str, action='store', help='path to save [default: ./data]', nargs='?',  const='./data')

v = sp.add_parser('verify_signature', help = 'verify signature')
splist.append(v)
v.add_argument('-k', type=str, action='store', help='path to keys [default: ./data]', nargs='?',  const='./data')
v.add_argument('-m', type=str, action='store', help='message')
v.add_argument('-s', type=str, action='store', help='path to signature [default: ./data]', nargs='?',  const='./data')


# collect and display for helps
helps = []
helps.append(parser.format_help())
for p in splist:
   helps.append(p.format_help())
print('\n'.join(helps))
args = parser.parse_args()
if args.command == "generate_keys":
   x, y = lsag.generate_keys(args.n, args.i)
   if args.k == None:
      lsag.export_public_keys(y)
      lsag.export_private_key(x, args.i)

if args.command == "generate_signature":
   if args.k == None:
      x = lsag.import_private_key(args.i)
      y = lsag.import_public_keys()
   signature = lsag.sign(x, args.i, args.m, y)
   if args.s == None:
      lsag.export_signature(y, args.m, signature)

if args.command == "verify_signature":
   if args.k == None:
      y = lsag.import_public_keys()
   if args.s == None:
      signature = lsag.import_signature()
   assert(lsag.verify(args.m, y, *signature))
