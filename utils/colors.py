import random


def generate_colors(n):
    colors = [(255, 0, 0), (0, 255, 0)]

    for i in range(2, n):
        max_distance = -1
        best_color = None

        for j in range(100):
            r = random.randint(0, 255)
            g = random.randint(0, 255)
            b = random.randint(0, 255)
            color = (r, g, b)

            min_distance = min([distance(color, c) for c in colors])

            if min_distance > max_distance:
                max_distance = min_distance
                best_color = color

        colors.append(best_color)

    return colors


def distance(c1, c2):
    r1, g1, b1 = c1
    r2, g2, b2 = c2
    return ((r1 - r2) ** 2 + (g1 - g2) ** 2 + (b1 - b2) ** 2) ** 0.5


def brightness(color):
    r, g, b = color
    y = 0.299 * r + 0.587 * g + 0.114 * b
    return y


def rgb2hex(color):
    r, g, b = color
    return '#%02x%02x%02x' % (r, g, b)
