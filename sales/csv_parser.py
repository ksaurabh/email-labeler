"""
CSV Parser Examples
Demonstrates different ways to parse CSV files in Python
"""

import csv
from pathlib import Path
import random
import secrets
import string

def random_integer(start, end):
    """Generate a random integer between start and end (inclusive)"""
    return random.randint(start, end)

# Example 1: Basic CSV parsing with csv.reader
def parse_csv_basic(filename):
    """
    Parse a CSV file using csv.reader (returns lists)
    """
    print(f"\n=== Parsing {filename} with csv.reader ===")

    with open(filename, 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)

        # Read header
        headers = next(csv_reader)
        print(f"Headers: {headers}")
        rows = []
        for row_num, row in enumerate(csv_reader, start=1):
            if (row[0] != "Sum" and row[0] != ''):
                rows.append(row)
        for row in rows:
            print(row)
        print()

        # Read data rows
        deals = []
        amounts = []
        for i in range(0, 100000):
            deals.append(0)
            amounts.append(0)
            # print(f"i={i}")
            # print(deals[i])
            for row in rows:
                chances = int(row[2].replace("%", ""))
                amount = float(row[1].replace("$", "").replace(",", ""))

                if(i < 10):
                    print(row)
                    print(amount)
                    print()

                rand = random_integer(0, 100)
                if(chances < rand):
                    deals[i] = deals[i]+1
                    amounts[i] = amounts[i]+amount

        sorted_sims = sorted(deals)
        sorted_amounts = sorted(amounts)
        # for s in sorted_sims:
        #     print(s)
        # print()

        print(f"Scenarios simulated = {len(sorted_sims)}")
        print()
        print(f"percentile\tdealcount \tamount")
        for i in range(0, 11):
            index = int((i * len(sorted_sims))/10)
            if(index == len(sorted_sims)):
                index = index - 1
            print(f"{i*10}% \t\t{sorted_sims[index] } \t\t{sorted_amounts[index]}")
        print()



# Example 2: CSV parsing with DictReader (returns dictionaries)
def parse_csv_dict(filename):
    """
    Parse a CSV file using csv.DictReader (returns dictionaries)
    Better for accessing data by column name
    """
    print(f"\n=== Parsing {filename} with csv.DictReader ===")

    with open(filename, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)

        for row_num, row in enumerate(csv_reader, start=1):
            print(f"Row {row_num}: {dict(row)}")


# Example 3: Parse and filter data
def parse_and_filter(filename, filter_column, filter_value):
    """
    Parse CSV and filter rows based on a condition
    """
    print(f"\n=== Filtering {filename} where {filter_column}={filter_value} ===")

    results = []
    with open(filename, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)

        for row in csv_reader:
            if row.get(filter_column) == filter_value:
                results.append(row)

    print(f"Found {len(results)} matching rows:")
    for row in results:
        print(row)

    return results


# Example 4: Parse and convert to list of dictionaries
def parse_to_list(filename):
    """
    Parse entire CSV into a list of dictionaries
    """
    data = []

    with open(filename, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        data = list(csv_reader)

    return data


# Example 5: Handle different delimiters and quote characters
def parse_csv_custom(filename, delimiter=',', quotechar='"'):
    """
    Parse CSV with custom delimiter (e.g., tab-separated, semicolon-separated)
    """
    print(f"\n=== Parsing {filename} with custom delimiter '{delimiter}' ===")

    with open(filename, 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file, delimiter=delimiter, quotechar=quotechar)

        for row in csv_reader:
            print(row)


# Example 6: Using pandas (more powerful for data analysis)
def parse_with_pandas(filename):
    """
    Parse CSV using pandas library (install with: pip install pandas)
    """
    try:
        import pandas as pd

        print(f"\n=== Parsing {filename} with pandas ===")

        # Read CSV into DataFrame
        df = pd.read_csv(filename)

        print(f"Shape: {df.shape}")
        print(f"\nFirst 5 rows:")
        print(df.head())

        print(f"\nColumn names:")
        print(df.columns.tolist())

        print(f"\nData types:")
        print(df.dtypes)

        return df

    except ImportError:
        print("pandas is not installed. Install it with: pip install pandas")
        return None


# Example usage and demo
if __name__ == "__main__":
    # Create a sample CSV file for demonstration
    sample_csv = "qbr-fy26q4.csv"

    print("Sample CSV file created!")

    # Run examples
    parse_csv_basic(sample_csv)
    # parse_csv_dict(sample_csv)
    # parse_and_filter(sample_csv, "city", "New York")
    #
    # # Parse to list
    # all_data = parse_to_list(sample_csv)
    # print(f"\n=== Parsed {len(all_data)} total rows ===")
    #
    # # Try pandas (if available)
    # parse_with_pandas(sample_csv)
    #
    # print("\n" + "=" * 50)
    # print("To use this code with your own CSV file:")
    # print("1. Replace 'sample_csv' with your file path")
    # print("2. Choose the parsing method that fits your needs")
    # print("3. Modify the examples as needed")
    # print("=" * 50)