export function didFromDidUrl(didUrl: string): string {
  return didUrl.split('?')[0]!;
}

export function areDidUrlsSameDid(didUrl1: string, didUrl2: string): boolean {
  return didFromDidUrl(didUrl1) === didFromDidUrl(didUrl2);
}
