import { buildMimcSponge, MimcSponge } from "circomlibjs";
import { Contract, EventLog } from "ethers";

export const TREE_LEVELS = 20;
export const SEED = "mimcsponge";

// = keccak256("tornado") % FIELD_SIZE
export const ZERO_VALUE = BigInt(
  "21663839004416932945382355908790599225266501822907911457504978515578255421292"
);

export function getRandomBigInt(max: bigint) {
  return BigInt(Math.floor(Math.random() * Number(max.toString())));
}

export function toFixedHex(number: BigInt, length = 32) {
  let str = number.toString(16);
  while (str.length < length * 2) str = "0" + str;
  str = "0x" + str;
  return str;
}

function calculateHash(mimc: MimcSponge, left: any, right: any) {
  return BigInt(mimc.F.toString(mimc.multiHash([left, right])));
}

export function generateZeros(mimc: MimcSponge, levels: number) {
  let zeros = [];
  zeros[0] = ZERO_VALUE;
  for (let i = 1; i <= levels; i++)
    zeros[i] = calculateHash(mimc, zeros[i - 1], zeros[i - 1]);
  return zeros;
}

export async function calculateMerkleRootAndPathFromEvents(
  address: string,
  provider: any,
  levels: number,
  element: any
) {
  const abi = [
    "event Commit(bytes32 indexed commitment,uint32 leafIndex,uint256 timestamp)",
  ];
  const contract = new Contract(address, abi, provider);
  const events = (await contract.queryFilter(
    contract.filters.Commit()
  )) as EventLog[];
  let commitments = [];
  for (let event of events) {
    commitments.push(BigInt(event.args.commitment));
  }
  return await calculateMerkleRootAndPath(levels, commitments, element);
}

// calculates Merkle root from elements and a path to the given element
export async function calculateMerkleRootAndPath(
  levels: number,
  elements: any[],
  element?: any
) {
  const mimc = await buildMimcSponge();

  const capacity = 2 ** levels;
  if (elements.length > capacity) throw new Error("Tree is full");

  const zeros = generateZeros(mimc, levels);
  let layers = [];
  layers[0] = elements.slice();
  for (let level = 1; level <= levels; level++) {
    layers[level] = [];

    for (let i = 0; i < Math.ceil(layers[level - 1].length / 2); i++) {
      layers[level][i] = calculateHash(
        mimc,
        layers[level - 1][i * 2],
        i * 2 + 1 < layers[level - 1].length
          ? layers[level - 1][i * 2 + 1]
          : zeros[level - 1]
      );
    }
  }

  const root =
    layers[levels].length > 0 ? layers[levels][0] : zeros[levels - 1];

  let pathElements = [];
  let pathIndices = [];

  if (element) {
    const bne = BigInt(element);
    let index = layers[0].findIndex((e) => BigInt(e) === bne);
    // console.log('idx: ' + index)
    for (let level = 0; level < levels; level++) {
      pathIndices[level] = index % 2;
      pathElements[level] =
        (index ^ 1) < layers[level].length
          ? layers[level][index ^ 1]
          : zeros[level];
      index >>= 1;
    }
  }

  return {
    root: root.toString(),
    pathElements: pathElements.map((v) => v.toString()),
    pathIndices: pathIndices.map((v) => v.toString()),
  };
}
