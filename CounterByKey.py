from collections import defaultdict
from typing import Any, Literal


class CounterByKey:
    def __init__(self):
        self.counts = defaultdict(int)

    def add(self, key: Any) -> None:
        """Add an item to be counted."""
        self.counts[key] += 1

    def add_many(self, keys: list) -> None:
        """Add multiple items at once."""
        for key in keys:
            self.counts[key] += 1

    def get_count(self, key: Any) -> int:
        """Get the count for a specific key."""
        return self.counts.get(key, 0)

    def print_by_count(self, order: Literal['asc', 'desc'] = 'desc') -> None:
        """Print all items sorted by their count.

        Args:
            order: 'asc' for ascending (lowest to highest) or 'desc' for descending (highest to lowest)
        """
        reverse = order == 'desc'
        sorted_items = sorted(self.counts.items(), key=lambda x: x[1], reverse=reverse)

        for key, count in sorted_items:
            print(f"{key}: {count}")

    def get_sorted_items(self, order: Literal['asc', 'desc'] = 'desc') -> list[tuple[Any, int]]:
        """Return sorted items as a list of (key, count) tuples."""
        reverse = order == 'desc'
        return sorted(self.counts.items(), key=lambda x: x[1], reverse=reverse)

    def clear(self) -> None:
        """Clear all counts."""
        self.counts.clear()