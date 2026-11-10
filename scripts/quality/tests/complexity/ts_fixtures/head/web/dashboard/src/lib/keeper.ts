// Fixture head state: added file pinning class-body extraction. Getter
// `value` (cognitive 1, one if), setter `value` (cognitive 3: if + else-if
// link + else) and method `bump` (cognitive 3: for + nested if at nesting 1)
// are each measured as their own body under the class scope.
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
