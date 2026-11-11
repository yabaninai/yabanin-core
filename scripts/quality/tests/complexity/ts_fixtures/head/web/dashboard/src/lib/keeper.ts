// Fixture head state: added file pinning class bodies — getter value (1),
// setter value (3) and method bump (3), each measured as its own body.
export class ScoreKeeper {
  private current = 0;

  get value(): number {
    if (this.current > 100) return 100;
    return this.current;
  }

  set value(next: number) {
    if (next < 0) this.current = 0;
    else if (next > 100) this.current = 100;
    else this.current = next;
  }

  bump(step: number): number {
    let total = 0;
    for (let index = 0; index < step; index += 1) {
      if (index % 2 === 0) total += index;
    }
    return total;
  }
}
